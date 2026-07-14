//! rbuild-server — runs inside the build container.
//!
//! Env:
//!   RBUILD_AUTHORIZED_KEYS  openssh pubkey lines, newline-separated (required)
//!   RBUILD_HOST_KEY         path to the ed25519 host key (default /etc/rbuild/host_key)
//!   RBUILD_SRC              default /src
//!   RBUILD_TARGETS          default /targets
//!   RBUILD_BIND             default 0.0.0.0:7878

use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

use cargo_rbuild::*;
use rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.into())
}

fn main() -> io::Result<()> {
    let authorized: Vec<PublicKey> = std::env::var("RBUILD_AUTHORIZED_KEYS")
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| PublicKey::from_openssh(l).ok())
        .collect();
    if authorized.is_empty() {
        eprintln!("rbuild-server: RBUILD_AUTHORIZED_KEYS is empty or unparseable");
        std::process::exit(1);
    }

    let host_key = load_or_create_host_key(&env_or("RBUILD_HOST_KEY", "/etc/rbuild/host_key"))?;
    let fp = host_key.public_key().fingerprint(HashAlg::Sha256);
    let bind = env_or("RBUILD_BIND", "0.0.0.0:7878");

    let listener = TcpListener::bind(&bind)?;
    eprintln!("rbuild-server listening on {bind}");
    eprintln!("host key {fp}");
    eprintln!("{} authorized key(s)", authorized.len());

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let authorized = authorized.clone();
        let host_key = host_key.clone();
        thread::spawn(move || {
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into());
            if let Err(e) = serve(stream, &authorized, &host_key) {
                eprintln!("[{peer}] {e}");
            }
        });
    }
    Ok(())
}

fn load_or_create_host_key(path: &str) -> io::Result<PrivateKey> {
    let p = Path::new(path);
    if p.exists() {
        return PrivateKey::read_openssh_file(p).map_err(io::Error::other);
    }
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(io::Error::other)?;
    key.write_openssh_file(p, LineEnding::LF)
        .map_err(io::Error::other)?;
    eprintln!("generated new host key at {path}");
    Ok(key)
}

fn serve(stream: TcpStream, authorized: &[PublicKey], host_key: &PrivateKey) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let mut r = BufReader::with_capacity(CHUNK, stream.try_clone()?);
    let mut w = BufWriter::with_capacity(CHUNK, stream);

    // ---- handshake ------------------------------------------------------
    let mut nonce = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    send(
        &mut w,
        &ServerMsg::Hello {
            nonce: nonce.clone(),
            host_pubkey: host_key
                .public_key()
                .to_openssh()
                .map_err(io::Error::other)?,
        },
    )?;

    let ClientMsg::Auth { pubkey, sig_pem } = recv(&mut r)? else {
        send(&mut w, &ServerMsg::Error("expected Auth".into()))?;
        return Err(io::Error::other("protocol: expected Auth"));
    };

    let key = PublicKey::from_openssh(&pubkey).map_err(io::Error::other)?;
    let sig = SshSig::from_pem(sig_pem.as_bytes()).map_err(io::Error::other)?;

    // The signature must be over the nonce *we* just generated, so a captured
    // signature from an earlier session is worthless.
    let known = authorized.iter().any(|k| k.key_data() == key.key_data());
    if !known || key.verify(NAMESPACE, &nonce, &sig).is_err() {
        send(&mut w, &ServerMsg::Error("auth denied".into()))?;
        return Err(io::Error::other("auth denied"));
    }
    send(&mut w, &ServerMsg::AuthOk)?;

    let src_root = PathBuf::from(env_or("RBUILD_SRC", "/src"));
    let tgt_root = PathBuf::from(env_or("RBUILD_TARGETS", "/targets"));

    // ---- request loop ---------------------------------------------------
    loop {
        let msg: ClientMsg = match recv(&mut r) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };

        match msg {
            ClientMsg::Bye => return Ok(()),
            ClientMsg::Auth { .. } => {
                send(&mut w, &ServerMsg::Error("already authenticated".into()))?;
            }

            ClientMsg::Manifest { project } => {
                if !valid_project(&project) {
                    send(&mut w, &ServerMsg::Error("bad project name".into()))?;
                    continue;
                }
                let dir = src_root.join(&project);
                let mut out = Vec::new();
                walk(&dir, &dir, &mut out);
                send(&mut w, &ServerMsg::Manifest(out))?;
            }

            ClientMsg::Push {
                project,
                deletes,
                files,
            } => {
                if !valid_project(&project) {
                    send(&mut w, &ServerMsg::Error("bad project name".into()))?;
                    // The client is about to stream bodies we can't place, so
                    // the stream is now unrecoverable. Drop the connection.
                    return Err(io::Error::other("bad project name on push"));
                }
                let dir = src_root.join(&project);
                fs::create_dir_all(&dir)?;

                for d in &deletes {
                    if valid_rel(d) {
                        let _ = fs::remove_file(dir.join(d));
                    }
                }

                let mut received = 0u64;
                let mut buf = vec![0u8; CHUNK];
                for h in &files {
                    if !valid_rel(&h.path) {
                        return Err(io::Error::other(format!("bad path {}", h.path)));
                    }
                    let dst = dir.join(&h.path);
                    if let Some(p) = dst.parent() {
                        fs::create_dir_all(p)?;
                    }
                    let mut f = BufWriter::new(fs::File::create(&dst)?);
                    let mut left = h.size;
                    while left > 0 {
                        let want = left.min(buf.len() as u64) as usize;
                        r.read_exact(&mut buf[..want])?;
                        f.write_all(&buf[..want])?;
                        left -= want as u64;
                        received += want as u64;
                    }
                    f.flush()?;
                    drop(f);
                    // Cargo fingerprints on mtime, so it has to survive the wire.
                    set_mtime(&dst, h.mtime)?;
                }
                send(&mut w, &ServerMsg::PushOk { received })?;
            }

            ClientMsg::Build {
                project,
                subcommand,
                args,
                target,
                trailing,
            } => {
                if !valid_project(&project) {
                    send(&mut w, &ServerMsg::Error("bad project name".into()))?;
                    continue;
                }

                let tdir = match target {
                    Some(_) => tgt_root.join(&project),
                    None => tgt_root.join(format!("{project}-native")),
                };

                let code = run_cargo(
                    &mut w,
                    &src_root.join(&project),
                    &tdir,
                    &subcommand,
                    &args,
                    target.as_deref(),
                    &trailing,
                )?;

                send(&mut w, &ServerMsg::Exit(code))?;
            }

            ClientMsg::Fetch { project, rel } => {
                if !valid_project(&project) || !valid_rel(&rel) {
                    send(&mut w, &ServerMsg::Error("bad path".into()))?;
                    continue;
                }
                let path = tgt_root.join(&project).join(&rel);
                match fs::File::open(&path) {
                    Err(e) => send(
                        &mut w,
                        &ServerMsg::Error(format!("{}: {e}", path.display())),
                    )?,
                    Ok(f) => {
                        let mut f = BufReader::with_capacity(CHUNK, f);
                        let mut buf = vec![0u8; CHUNK];
                        loop {
                            let n = f.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            send(&mut w, &ServerMsg::Data(buf[..n].to_vec()))?;
                        }
                        send(&mut w, &ServerMsg::DataEnd)?;
                    }
                }
            }
        }
    }
}

/// Spawn cargo directly — no shell, so nothing in `args` can be interpreted.
/// stdout and stderr are pumped by two threads into one channel and forwarded
/// as they arrive, which is what makes the client's output feel live.
fn run_cargo<W: Write>(
    w: &mut W,
    cwd: &Path,
    target_dir: &Path,
    subcommand: &str,
    args: &[String],
    target: Option<&str>,
    trailing: &[String],
) -> io::Result<i32> {
    if !cwd.is_dir() {
        send(
            w,
            &ServerMsg::Error(format!("{} not synced", cwd.display())),
        )?;
        return Ok(1);
    }

    let mut cmd = Command::new("cargo");
    match target {
        // cross: xwin supplies the MSVC sysroot and lld-link
        Some(t) => {
            cmd.arg("xwin").arg(subcommand).arg("--target").arg(t);
        }

        // native: plain cargo, runs here
        None => {
            cmd.arg(subcommand);
        }
    }

    cmd.args(args);

    if !trailing.is_empty() {
        cmd.arg("--").args(trailing);
    }

    let mut child = cmd
        .current_dir(cwd)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_TERM_COLOR", "always")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut pumps = Vec::new();
    if let Some(out) = child.stdout.take() {
        pumps.push(spawn_pump(out, tx.clone()));
    }
    if let Some(err) = child.stderr.take() {
        pumps.push(spawn_pump(err, tx.clone()));
    }
    drop(tx); // last sender goes with the pumps; rx ends when both close

    for chunk in rx {
        send(w, &ServerMsg::Output(chunk))?;
    }
    for p in pumps {
        let _ = p.join();
    }

    Ok(child.wait()?.code().unwrap_or(1))
}

fn spawn_pump<R: Read + Send + 'static>(
    mut r: R,
    tx: mpsc::Sender<Vec<u8>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = vec![0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<FileHeader>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(md) = e.metadata() else { continue };
        if md.is_dir() {
            walk(root, &p, out);
        } else if md.is_file() {
            let Ok(rel) = p.strip_prefix(root) else {
                continue;
            };
            let rel = rel
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/");
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            out.push(FileHeader {
                path: rel,
                size: md.len(),
                mtime,
            });
        }
    }
}

#[cfg(unix)]
fn set_mtime(path: &Path, secs: i64) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let times = [
        libc_timeval {
            tv_sec: secs,
            tv_usec: 0,
        },
        libc_timeval {
            tv_sec: secs,
            tv_usec: 0,
        },
    ];
    // utimes(2) — avoids pulling in the whole libc crate for one call
    extern "C" {
        fn utimes(path: *const std::ffi::c_char, times: *const libc_timeval) -> i32;
    }
    let rc = unsafe { utimes(c.as_ptr(), times.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
#[repr(C)]
struct libc_timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[cfg(not(unix))]
fn set_mtime(_path: &Path, _secs: i64) -> io::Result<()> {
    Ok(())
}
