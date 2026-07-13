//! rbuild — client. Run from the project directory.
//!
//!   rbuild                     cargo build
//!   rbuild run                 build, then execute locally
//!   rbuild run -- --flag x     build, execute with args
//!   rbuild check
//!   rbuild clippy -- -D warnings
//!   rbuild build --release
//!   rbuild --full build        force a full re-upload
//!
//! Env:
//!   RBUILD_HOST   default "truenas.lan"
//!   RBUILD_KEY    default ~/.ssh/id_ed25519

use ignore::WalkBuilder;
use rbuild::*;
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant, UNIX_EPOCH};

const TARGET: &str = "x86_64-pc-windows-msvc";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let full = raw.iter().any(|a| a == "--full");
    let mut rest: Vec<String> = raw.into_iter().filter(|a| a != "--full").collect();

    let mut sub = if rest.is_empty() {
        "build".to_string()
    } else {
        rest.remove(0)
    };

    // `cargo run` on a Linux host cross-compiling to Windows would try to exec
    // a PE binary. Downgrade to `build`; we execute it here instead.
    let mut run = false;
    if sub == "run" {
        sub = "build".into();
        run = true;
    }

    let exe_args: Vec<String> = match rest.iter().position(|a| a == "--") {
        Some(i) => rest.split_off(i).into_iter().skip(1).collect(),
        None => Vec::new(),
    };
    let cargo_args = rest;

    let produces = sub == "build";
    if !produces {
        run = false;
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return die(&format!("cwd: {e}")),
    };
    let Some(proj) = cwd.file_name().and_then(|s| s.to_str()).map(String::from) else {
        return die("cannot derive project name from cwd");
    };
    if !valid_project(&proj) {
        return die(&format!("project name {proj:?} has characters I won't send"));
    }
    let profile = if cargo_args.iter().any(|a| a == "--release") {
        "release"
    } else {
        "debug"
    };
    let out_dir = cwd.join("target").join("remote").join(profile);
    let exe_name = format!("{proj}.exe");

    match remote(&cwd, &proj, &sub, &cargo_args, &TARGET.to_string(), profile, &out_dir, &exe_name, produces, full) {
        Ok(Some(code)) => {
            if code != 0 {
                return ExitCode::from(code.min(255) as u8);
            }
        }
        Ok(None) => {} // handled: fall through to run
        Err(e) => {
            eprintln!("[rbuild] {e} — building locally");
            return local(&sub, &cargo_args, produces, run, profile, &proj, &out_dir, &exe_args);
        }
    }

    if run {
        return exec_local(&out_dir.join(&exe_name), &exe_args);
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn remote(
    cwd: &Path,
    proj: &str,
    sub: &str,
    cargo_args: &[String],
    target: &str,
    profile: &str,
    out_dir: &Path,
    exe_name: &str,
    produces: bool,
    full: bool,
) -> io::Result<Option<i32>> {
    let host = std::env::var("RBUILD_HOST").unwrap_or_else(|_| "truenas.lan".into());
    let addr = (host.as_str(), PORT)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("no address"))?;

    let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    sock.set_nodelay(true)?;
    let mut r = BufReader::with_capacity(CHUNK, sock.try_clone()?);
    let mut w = BufWriter::with_capacity(CHUNK, sock);

    // ---- handshake ------------------------------------------------------
    let ServerMsg::Hello { nonce, host_pubkey } = recv(&mut r)? else {
        return Err(io::Error::other("expected Hello"));
    };
    verify_host(&host, &host_pubkey)?;

    let key = load_key()?;
    let sig = key
        .sign(NAMESPACE, HashAlg::Sha512, &nonce)
        .map_err(io::Error::other)?;
    send(
        &mut w,
        &ClientMsg::Auth {
            pubkey: key.public_key().to_openssh().map_err(io::Error::other)?,
            sig_pem: sig.to_pem(LineEnding::LF).map_err(io::Error::other)?,
        },
    )?;
    match recv::<ServerMsg, _>(&mut r)? {
        ServerMsg::AuthOk => {}
        ServerMsg::Error(e) => return Err(io::Error::other(format!("auth: {e}"))),
        _ => return Err(io::Error::other("expected AuthOk")),
    }

    // ---- sync -----------------------------------------------------------
    let t = Instant::now();
    let local_files = scan_local(cwd)?;

    let remote_files: HashMap<String, FileHeader> = if full {
        HashMap::new()
    } else {
        send(&mut w, &ClientMsg::Manifest { project: proj.into() })?;
        match recv::<ServerMsg, _>(&mut r)? {
            ServerMsg::Manifest(v) => v.into_iter().map(|h| (h.path.clone(), h)).collect(),
            ServerMsg::Error(e) => return Err(io::Error::other(e)),
            _ => return Err(io::Error::other("expected Manifest")),
        }
    };

    // rsync's quick check: size or mtime differs -> resend. 1s tolerance,
    // because NTFS and ext4 disagree about granularity.
    let mut upload: Vec<FileHeader> = local_files
        .values()
        .filter(|h| match remote_files.get(&h.path) {
            Some(rh) => rh.size != h.size || (rh.mtime - h.mtime).abs() > 1,
            None => true,
        })
        .cloned()
        .collect();
    upload.sort_by(|a, b| a.path.cmp(&b.path));

    let deletes: Vec<String> = remote_files
        .keys()
        .filter(|p| !local_files.contains_key(*p))
        .cloned()
        .collect();

    if !upload.is_empty() || !deletes.is_empty() {
        send(
            &mut w,
            &ClientMsg::Push {
                project: proj.into(),
                deletes: deletes.clone(),
                files: upload.clone(),
            },
        )?;
        let sent = stream_bodies(&mut w, cwd, &upload)?;
        w.flush()?;

        match recv::<ServerMsg, _>(&mut r)? {
            ServerMsg::PushOk { .. } => {
                let s = t.elapsed().as_secs_f64();
                eprintln!(
                    "[rbuild] sync: {} up, {} del, {} in {:.1}s",
                    upload.len(),
                    deletes.len(),
                    human(sent),
                    s
                );
            }
            ServerMsg::Error(e) => return Err(io::Error::other(e)),
            _ => return Err(io::Error::other("expected PushOk")),
        }
    } else {
        eprintln!("[rbuild] sync: up to date");
    }

    // ---- build ----------------------------------------------------------
    send(
        &mut w,
        &ClientMsg::Build {
            project: proj.into(),
            subcommand: sub.into(),
            args: cargo_args.to_vec(),
            target: target.into(),
        },
    )?;

    let mut err = io::stderr();
    let code = loop {
        match recv::<ServerMsg, _>(&mut r)? {
            ServerMsg::Output(chunk) => {
                err.write_all(&chunk)?;
                err.flush()?;
            }
            ServerMsg::Exit(c) => break c,
            ServerMsg::Error(e) => return Err(io::Error::other(e)),
            _ => return Err(io::Error::other("unexpected message during build")),
        }
    };
    if code != 0 {
        // cargo has spoken. Its verdict stands — rebuilding locally would only
        // reprint the same errors, slower.
        let _ = send(&mut w, &ClientMsg::Bye);
        return Ok(Some(code));
    }

    // ---- fetch ----------------------------------------------------------
    if produces {
        let rel = format!("{target}/{profile}/{exe_name}");
        send(
            &mut w,
            &ClientMsg::Fetch {
                project: proj.into(),
                rel,
            },
        )?;
        fs::create_dir_all(out_dir)?;
        let tmp = out_dir.join(format!("{exe_name}.part"));
        let mut n = 0u64;
        {
            let mut f = BufWriter::new(fs::File::create(&tmp)?);
            loop {
                match recv::<ServerMsg, _>(&mut r)? {
                    ServerMsg::Data(d) => {
                        f.write_all(&d)?;
                        n += d.len() as u64;
                    }
                    ServerMsg::DataEnd => break,
                    ServerMsg::Error(e) => {
                        let _ = fs::remove_file(&tmp);
                        return Err(io::Error::other(format!("fetch: {e}")));
                    }
                    _ => return Err(io::Error::other("unexpected message during fetch")),
                }
            }
            f.flush()?;
        }
        // rename last, so a half-written exe never masquerades as a good one
        fs::rename(&tmp, out_dir.join(exe_name))?;
        eprintln!("[rbuild] {} -> target\\remote\\{profile}\\{exe_name}", human(n));
    }

    let _ = send(&mut w, &ClientMsg::Bye);
    Ok(Some(0))
}

/// Raw bodies, back to back, in the same order as the headers. No per-file
/// framing — the server already knows every size.
fn stream_bodies<W: Write>(w: &mut W, root: &Path, files: &[FileHeader]) -> io::Result<u64> {
    let total: u64 = files.iter().map(|h| h.size).sum();
    let mut sent = 0u64;
    let mut buf = vec![0u8; CHUNK];
    let mut last = Instant::now();

    for h in files {
        let path = root.join(h.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let mut f = fs::File::open(&path)?;
        let mut left = h.size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                // File shrank between the scan and now. The header already
                // promised `size` bytes, so pad rather than desync the stream.
                let pad = vec![0u8; left as usize];
                w.write_all(&pad)?;
                sent += left;
                break;
            }
            w.write_all(&buf[..n])?;
            left -= n as u64;
            sent += n as u64;
        }
        if last.elapsed() > Duration::from_millis(120) && total > 1 << 20 {
            eprint!("\r[rbuild] uploading {}/{}   ", human(sent), human(total));
            let _ = io::stderr().flush();
            last = Instant::now();
        }
    }
    if total > 1 << 20 {
        eprint!("\r                                          \r");
    }
    Ok(sent)
}

/// Honours .gitignore. Dotfiles included (.cargo/config.toml is real);
/// .git and target/ never are.
fn scan_local(root: &Path) -> io::Result<HashMap<String, FileHeader>> {
    let mut out = HashMap::new();
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .filter_entry(|e| {
            let n = e.file_name();
            n != ".git" && n != "target"
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        let Ok(rel) = entry.path().strip_prefix(root) else {
            continue;
        };
        let rel = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join("/");
        if rel.is_empty() || !valid_rel(&rel) {
            continue;
        }
        let Ok(modified) = md.modified() else { continue };
        let mtime = modified
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        out.insert(
            rel.clone(),
            FileHeader {
                path: rel,
                size: md.len(),
                mtime,
            },
        );
    }
    Ok(out)
}

// ---- keys ---------------------------------------------------------------

fn key_path() -> PathBuf {
    if let Ok(p) = std::env::var("RBUILD_KEY") {
        return PathBuf::from(p);
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    PathBuf::from(home).join(".ssh").join("id_ed25519")
}

fn load_key() -> io::Result<PrivateKey> {
    let path = key_path();
    let mut key = PrivateKey::read_openssh_file(&path).map_err(|e| {
        io::Error::other(format!("reading {}: {e}", path.display()))
    })?;
    if key.is_encrypted() {
        let pw = rpassword::prompt_password(format!("passphrase for {}: ", path.display()))?;
        key = key.decrypt(pw).map_err(io::Error::other)?;
    }
    Ok(key)
}

/// Trust on first use, then pin — the same bargain as known_hosts.
fn verify_host(host: &str, pubkey: &str) -> io::Result<()> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    let dir = PathBuf::from(home).join(".rbuild");
    fs::create_dir_all(&dir)?;
    let file = dir.join("known_hosts");

    let fp = ssh_key::PublicKey::from_openssh(pubkey)
        .map_err(io::Error::other)?
        .fingerprint(HashAlg::Sha256)
        .to_string();

    let existing = fs::read_to_string(&file).unwrap_or_default();
    for line in existing.lines() {
        if let Some((h, f)) = line.split_once(' ') {
            if h == host {
                if f == fp {
                    return Ok(());
                }
                return Err(io::Error::other(format!(
                    "HOST KEY CHANGED for {host}\n  expected {f}\n  got      {fp}\n\
                     If you rebuilt the container, delete the line from {}",
                    file.display()
                )));
            }
        }
    }

    eprintln!("[rbuild] pinning new host key for {host}: {fp}");
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&file)?;
    writeln!(f, "{host} {fp}")?;
    Ok(())
}

// ---- local fallback -----------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn local(
    sub: &str,
    args: &[String],
    produces: bool,
    run: bool,
    profile: &str,
    proj: &str,
    out_dir: &Path,
    exe_args: &[String],
) -> ExitCode {
    let status = Command::new("cargo").arg(sub).args(args).status();
    let code = match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => return die(&format!("cargo: {e}")),
    };
    if code != 0 {
        return ExitCode::from(code.min(255) as u8);
    }
    let exe = format!("{proj}.exe");
    if produces {
        let _ = fs::create_dir_all(out_dir);
        let _ = fs::copy(
            PathBuf::from("target").join(profile).join(&exe),
            out_dir.join(&exe),
        );
    }
    if run {
        return exec_local(&out_dir.join(&exe), exe_args);
    }
    ExitCode::SUCCESS
}

fn exec_local(exe: &Path, args: &[String]) -> ExitCode {
    if !exe.exists() {
        return die(&format!("no binary at {}", exe.display()));
    }
    eprintln!("[rbuild] running {}", exe.display());
    // cwd stays the crate root, matching `cargo run` — don't "fix" this
    match Command::new(exe).args(args).status() {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).min(255) as u8),
        Err(e) => die(&format!("exec: {e}")),
    }
}

fn human(n: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn die(msg: &str) -> ExitCode {
    eprintln!("[rbuild] error: {msg}");
    ExitCode::FAILURE
}
