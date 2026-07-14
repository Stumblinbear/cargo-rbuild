//! rbuild — client. Run from the project directory.
//!
//! The server builds; this machine runs what it built. Whatever cargo would have
//! executed, rbuild fetches and executes here, and cargo's own JSON says which
//! file that is, hash and all.
//!
//!   rbuild                     cargo build
//!   rbuild run                 build, then execute locally
//!   rbuild run -- --flag x     build, execute with args
//!   rbuild run --example foo   build the example, execute it
//!   rbuild bench --bench perf  build the bench, execute it here
//!   rbuild test                build the test binaries, execute them here
//!   rbuild build --bin foo
//!   rbuild check
//!   rbuild clippy -- -D warnings
//!   rbuild build --release
//!   rbuild --full build        force a full re-upload
//!
//! `--remote` is the one thing that moves execution to the server, for a
//! measurement the laptop must not contend with:
//!
//!   rbuild run --remote --release --example perf -- a.psd
//!   rbuild bench --remote --bench perf
//!   rbuild test --remote       includes the doctests, which cannot be fetched
//!
//! Env:
//!   RBUILD_HOST   default "truenas.lan"
//!   RBUILD_PORT   default 7878
//!   RBUILD_KEY    default ~/.ssh/id_ed25519

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf, MAIN_SEPARATOR_STR};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant, UNIX_EPOCH};

use cargo_rbuild::*;
use ignore::WalkBuilder;
use serde::Deserialize;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

const TARGET: &str = "x86_64-pc-windows-msvc";
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);
const PASSTHROUGH: [&str; 7] = ["build", "check", "clippy", "test", "bench", "run", "doc"];

fn main() -> ExitCode {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();

    // Cargo re-passes the subcommand name as argv[1]; a direct call doesn't.
    if raw.first().map(String::as_str) == Some("rbuild") {
        raw.remove(0);
    }

    let full = raw.iter().any(|a| a == "--full");
    let native = raw.iter().any(|a| a == "--native");
    let exec = raw.iter().any(|a| a == "--remote");
    let mut rest: Vec<String> = raw
        .into_iter()
        .filter(|a| !matches!(a.as_str(), "--full" | "--native" | "--remote"))
        .collect();

    let mut sub = if rest.is_empty() {
        "build".into()
    } else {
        rest.remove(0)
    };

    if !PASSTHROUGH.contains(&sub.as_str()) {
        return die(&format!("unknown subcommand {sub:?}"));
    }

    // Where a program executes is said, never inferred. Without --remote every
    // subcommand that runs something runs it here, off a fetched binary, whatever
    // kind of target it was built from.
    let here = if exec {
        Local::None
    } else {
        match sub.as_str() {
            "run" => Local::One,
            // cargo runs every test or bench binary it built, and so do we.
            "test" | "bench" => Local::Every,
            _ => Local::None,
        }
    };

    if exec && !matches!(sub.as_str(), "run" | "test" | "bench") {
        return die(&format!(
            "--remote executes a program, and `cargo {sub}` doesn't run one.\n  \
             To build on the server for its own platform: cargo rbuild {sub} --native"
        ));
    }
    if native && here != Local::None {
        return die(&format!(
            "--native builds for the server's platform, which this machine can't execute.\n  \
             To run it there too: cargo rbuild {sub} --remote"
        ));
    }

    let orig_sub = sub.clone();
    // Everything we execute here, we execute ourselves, off the fetched file.
    // The server only ever builds it.
    if here != Local::None {
        sub = "build".into();
    }

    let mut exe_args: Vec<String> = match rest.iter().position(|a| a == "--") {
        Some(i) => rest.split_off(i).into_iter().skip(1).collect(),
        None => Vec::new(),
    };
    let mut cargo_args = rest;

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return die(&format!("cwd: {e}")),
    };
    let Some(proj) = cwd.file_name().and_then(|s| s.to_str()).map(String::from) else {
        return die("cannot derive project name from cwd");
    };
    if !valid_project(&proj) {
        return die(&format!(
            "project name {proj:?} has characters I won't send"
        ));
    }

    // Only a cross build leaves behind a binary this machine can run.
    let fetching = !exec && !native && matches!(sub.as_str(), "build");

    // What the user actually typed, for a fallback that has no server to plan
    // around.
    let typed = cargo_args.clone();

    if fetching {
        if let Err(e) = plan(&cwd, &proj, &orig_sub, here, &mut cargo_args) {
            return die(&e);
        }
    }

    // `cargo build -- x` forwards x to rustc, so argv for a program we run here
    // must not ride along with the build. Under --remote the one cargo command
    // both builds and runs, so there it is exactly the program's argv.
    let trailing: &[String] = if here == Local::None { &exe_args } else { &[] };

    let mode = if exec {
        Mode::Exec
    } else if fetching {
        Mode::Fetch(here)
    } else {
        Mode::Plain
    };

    let built = match remote(
        &cwd,
        &proj,
        &sub,
        &cargo_args,
        if exec || native { None } else { Some(TARGET) },
        trailing,
        mode,
        full,
    ) {
        Ok(b) => b,

        // Falling back would run the program on the wrong machine, which is the
        // one thing --remote was asked not to do.
        Err(e) if exec => {
            return die(&format!(
                "remote run: {e}\n  If the host is up, its rbuild-server may predate --remote, \
                 which drops the connection right here. Rebuild and restart it: \
                 cargo build --release --bin rbuild-server"
            ));
        }

        Err(e) => {
            if e.raw_os_error() == Some(11001) {
                eprintln!("[rbuild] can't resolve host, check RBUILD_HOST. Building locally.");
            } else {
                eprintln!("[rbuild] {e} — building locally");
            }
            return local(&orig_sub, &typed, &exe_args);
        }
    };

    if built.code != 0 {
        return ExitCode::from(built.code.min(255) as u8);
    }

    // A libtest harness runs its benches only when asked, and cargo asks by
    // appending this. A `harness = false` bench sees it as one more argument,
    // which is what its own arg parsing is already written against.
    if orig_sub == "bench" {
        exe_args.push("--bench".into());
    }

    match here {
        Local::None => ExitCode::SUCCESS,
        Local::One => match built.exes.as_slice() {
            [exe] => exec_local(exe, &exe_args),
            // `plan` pins run to a single target, so cargo cannot have built two.
            other => die(&format!("expected one binary to run, cargo built {}", other.len())),
        },
        Local::Every => {
            if built.exes.is_empty() {
                eprintln!("[rbuild] nothing to run");
            }
            for exe in &built.exes {
                let code = exec_local(exe, &exe_args);
                if code != ExitCode::SUCCESS {
                    return code;
                }
            }
            ExitCode::SUCCESS
        }
    }
}

/// What runs on this machine once the server has built it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Local {
    None,
    /// The single binary `run` selected.
    One,
    /// Every binary the build produced, in the order cargo reported them, the
    /// way `cargo test` and `cargo bench` work through theirs.
    Every,
}

/// What the server is being asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Build for the server's platform and run it there, streaming.
    Exec,
    /// Cross-build, then fetch the binaries the local execution kind calls for.
    Fetch(Local),
    /// Build or check, and bring nothing back.
    Plain,
}

/// Rewrites `args` into the `cargo build` that produces what the subcommand
/// would have run, and refuses the cases where that binary would be ambiguous.
///
/// `cargo bench` and `cargo test` build and run in one step, so neither can hand
/// a binary back. `build` can, so that is what the server is asked for, with the
/// target flags the original subcommand implies.
fn plan(
    cwd: &Path,
    proj: &str,
    sub: &str,
    here: Local,
    args: &mut Vec<String>,
) -> Result<(), String> {
    if args.iter().any(|a| a.starts_with("--message-format")) {
        return Err("rbuild needs --message-format for itself: it reads cargo's JSON to learn \
                    the built binary's real filename"
            .into());
    }

    let chosen = !parse_flags(args)?.is_empty();
    match sub {
        // Ambiguity is the whole risk here: fetch the wrong binary and the user
        // watches something they didn't ask for. `select` refuses instead, and
        // then says out loud which target the bare `run` meant.
        "run" => {
            let one = select(cwd, proj, args, true)?;
            if !chosen {
                args.extend(one[0].flag());
            }
        }
        // `--benches` and `--tests` are cargo's own "every target with bench =
        // true / test = true", which is the set the bare subcommand would run.
        "bench" => {
            if !chosen {
                args.push("--benches".into());
            }
            // An unoptimised bench is not a measurement. `cargo bench` picks this
            // profile itself; `cargo build` would have used dev.
            let profiled = args
                .iter()
                .any(|a| a == "--release" || a.starts_with("--profile"));
            if !profiled {
                args.push("--profile".into());
                args.push("bench".into());
            }
            select(cwd, proj, args, false)?;
        }
        "test" => {
            if !chosen {
                args.push("--tests".into());
            }
            select(cwd, proj, args, false)?;
        }
        _ => {
            select(cwd, proj, args, false)?;
        }
    }

    if here == Local::Every && sub == "test" {
        // Not a limitation of the fetch: there is no file to fetch. rustdoc
        // compiles and runs a doctest in one step, on the machine holding the
        // source.
        eprintln!("[rbuild] doctests stay on the server. To include them: cargo rbuild test --remote");
    }

    // Cargo names each binary it produced, hash and all, so nothing here has to
    // reconstruct a filename.
    args.push("--message-format=json-render-diagnostics".into());
    Ok(())
}

// ---- target selection ---------------------------------------------------

/// The kinds of target that become an executable file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bin,
    Example,
    Test,
    Bench,
}

impl Kind {
    /// The word cargo uses for this kind, in a manifest, a flag and a JSON
    /// record alike.
    fn word(self) -> &'static str {
        match self {
            Kind::Bin => "bin",
            Kind::Example => "example",
            Kind::Test => "test",
            Kind::Bench => "bench",
        }
    }
}

/// An executable cargo will produce, named by the target it was built from.
#[derive(Clone)]
struct Artifact {
    kind: Kind,
    name: String,
}

impl Artifact {
    fn new(kind: Kind, name: String) -> Self {
        Artifact { kind, name }
    }

    /// The flag naming this and only this target, for a command line that left
    /// the choice implicit.
    fn flag(&self) -> [String; 2] {
        [format!("--{}", self.kind.word()), self.name.clone()]
    }

    fn label(&self) -> String {
        format!("--{} {}", self.kind.word(), self.name)
    }
}

/// A cargo target-selection flag, as written on the command line.
enum Flag {
    /// `--bin`, `--example`, `--test` or `--bench`, with the name it was given.
    One(Kind, String),
    /// `--bins`, `--examples`, `--tests` or `--benches`.
    All(Kind),
    Lib,
    AllTargets,
}

/// The selection flags in `args`, in order. `Err` names the malformed flag.
fn parse_flags(args: &[String]) -> Result<Vec<Flag>, String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        // A flag's value may be attached or separate; both reach cargo the same.
        let (head, attached) = match a.split_once('=') {
            Some((h, v)) => (h, Some(v.to_string())),
            None => (a.as_str(), None),
        };
        let mut value = |flag: &str| -> Result<String, String> {
            match attached.clone().or_else(|| it.next().cloned()) {
                Some(v) if !v.starts_with('-') => Ok(v),
                _ => Err(format!("{flag} needs a name")),
            }
        };
        out.push(match head {
            "--bin" => Flag::One(Kind::Bin, value("--bin")?),
            "--example" => Flag::One(Kind::Example, value("--example")?),
            "--test" => Flag::One(Kind::Test, value("--test")?),
            "--bench" => Flag::One(Kind::Bench, value("--bench")?),
            "--lib" => Flag::Lib,
            "--bins" => Flag::All(Kind::Bin),
            "--examples" => Flag::All(Kind::Example),
            "--tests" => Flag::All(Kind::Test),
            "--benches" => Flag::All(Kind::Bench),
            "--all-targets" => Flag::AllTargets,
            _ => continue,
        });
    }
    Ok(out)
}

/// The executable targets the given cargo args select.
///
/// `run` demands exactly one, so `rbuild run` can never launch a target other
/// than the one that was asked for. Which file each becomes is cargo's business,
/// not ours: it reports that in its JSON once the build has run.
fn select(cwd: &Path, proj: &str, args: &[String], run: bool) -> Result<Vec<Artifact>, String> {
    let flags = parse_flags(args)?;
    let meta = Meta::load(cwd);

    if flags.is_empty() {
        // cargo's default for `build`: the lib and every bin.
        let mut bins = match &meta {
            Ok(m) => m.named(Kind::Bin).to_vec(),
            // No manifest to read: the old guess, which is right for the common
            // single-bin crate and is what the remote build will look for too.
            Err(_) => vec![proj.to_string()],
        };
        if run && bins.len() > 1 {
            let Some(d) = meta.as_ref().ok().and_then(|m| m.default_run.clone()) else {
                bins.sort();
                return Err(format!(
                    "{} binaries ({}) and no `default-run` — say which with --bin <name>",
                    bins.len(),
                    bins.join(", ")
                ));
            };
            bins = vec![d];
        }
        return Ok(bins
            .into_iter()
            .map(|n| Artifact::new(Kind::Bin, n))
            .collect());
    }

    let mut out: Vec<Artifact> = Vec::new();
    for f in &flags {
        // The plural flags name no targets, so only they need the manifest.
        let listed = |k: Kind| -> Result<Vec<Artifact>, String> {
            let m = meta.as_ref().map_err(Clone::clone)?;
            Ok(m.named(k)
                .iter()
                .cloned()
                .map(|n| Artifact::new(k, n))
                .collect())
        };
        match f {
            Flag::Lib => {}
            Flag::One(k, n) => out.push(Artifact::new(*k, n.clone())),
            Flag::All(k) => out.extend(listed(*k)?),
            Flag::AllTargets => {
                for k in [Kind::Bin, Kind::Example, Kind::Test, Kind::Bench] {
                    out.extend(listed(k)?);
                }
            }
        }
    }

    // A name cargo doesn't know is a typo, and the remote build would fail on it
    // anyway. Say so before spending a build on it.
    if let Ok(m) = &meta {
        for a in &out {
            let known = m.named(a.kind);
            if !known.contains(&a.name) {
                let mut names = known.to_vec();
                names.sort();
                return Err(format!(
                    "no {} target named {:?} in {}. Available: {}",
                    a.kind.word(),
                    a.name,
                    m.package,
                    if names.is_empty() {
                        "(none)".into()
                    } else {
                        names.join(", ")
                    }
                ));
            }
        }
    }

    out.dedup_by(|a, b| a.kind == b.kind && a.name == b.name);

    if run && out.len() != 1 {
        return Err(if out.is_empty() {
            "no executable target selected to run".into()
        } else {
            format!(
                "run needs exactly one target, but {} were selected: {}",
                out.len(),
                out.iter()
                    .map(Artifact::label)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        });
    }
    Ok(out)
}

/// The target names cargo knows for this package, straight from its manifest.
struct Meta {
    package: String,
    bins: Vec<String>,
    examples: Vec<String>,
    tests: Vec<String>,
    benches: Vec<String>,
    default_run: Option<String>,
}

impl Meta {
    fn named(&self, kind: Kind) -> &[String] {
        match kind {
            Kind::Bin => &self.bins,
            Kind::Example => &self.examples,
            Kind::Test => &self.tests,
            Kind::Bench => &self.benches,
        }
    }
}

#[derive(Deserialize)]
struct MetaJson {
    packages: Vec<PkgJson>,
}

#[derive(Deserialize)]
struct PkgJson {
    name: String,
    manifest_path: String,
    default_run: Option<String>,
    targets: Vec<TgtJson>,
}

#[derive(Deserialize)]
struct TgtJson {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
}

impl Meta {
    /// Reads the manifest only — works even when the crate doesn't compile.
    fn load(cwd: &Path) -> Result<Meta, String> {
        let out = Command::new("cargo")
            .args(["metadata", "--no-deps", "--format-version=1"])
            .current_dir(cwd)
            .output()
            .map_err(|e| format!("cargo metadata: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "cargo metadata: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let meta: MetaJson =
            serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata: {e}"))?;

        let here = fs::canonicalize(cwd.join("Cargo.toml")).ok();
        let pkg = meta
            .packages
            .iter()
            .find(|p| fs::canonicalize(&p.manifest_path).ok() == here)
            .or(match meta.packages.as_slice() {
                [only] => Some(only),
                _ => None,
            })
            .ok_or("cwd is a workspace root, not a package — run rbuild from a package dir")?;

        // An example may be a lib (`crate-type = ["cdylib"]`); only bins run.
        let named = |k: &str| -> Vec<String> {
            pkg.targets
                .iter()
                .filter(|t| {
                    t.kind.iter().any(|x| x == k) && t.crate_types.iter().any(|c| c == "bin")
                })
                .map(|t| t.name.clone())
                .collect()
        };
        Ok(Meta {
            package: pkg.name.clone(),
            bins: named(Kind::Bin.word()),
            examples: named(Kind::Example.word()),
            tests: named(Kind::Test.word()),
            benches: named(Kind::Bench.word()),
            default_run: pkg.default_run.clone(),
        })
    }
}

/// What a remote cargo run left us with.
struct Built {
    code: i32,
    /// The fetched binaries, on this machine, in the order cargo reported them.
    exes: Vec<PathBuf>,
}

#[allow(clippy::too_many_arguments)]
fn remote(
    cwd: &Path,
    proj: &str,
    sub: &str,
    cargo_args: &[String],
    target: Option<&str>,
    trailing: &[String],
    mode: Mode,
    full: bool,
) -> io::Result<Built> {
    let host = std::env::var("RBUILD_HOST").unwrap_or_else(|_| "truenas.lan".into());
    let port: u16 = std::env::var("RBUILD_PORT")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(PORT);
    let addr = (host.as_str(), port)
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
        send(
            &mut w,
            &ClientMsg::Manifest {
                project: proj.into(),
            },
        )?;
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

    // ---- cargo, and under --remote the run too ---------------------------
    if mode == Mode::Exec {
        eprintln!("[rbuild] running {sub} on {host}");
    }
    send(
        &mut w,
        &ClientMsg::Cargo {
            project: proj.into(),
            subcommand: sub.into(),
            args: cargo_args.to_vec(),
            target: target.map(String::from),
            trailing: trailing.to_vec(),
        },
    )?;

    let mut out = io::stdout();
    let mut err = io::stderr();
    let mut records = Json::default();
    let code = loop {
        match recv::<ServerMsg, _>(&mut r)? {
            // A server too old for Chunk merges both streams into this one.
            ServerMsg::Output(chunk) => {
                err.write_all(&chunk)?;
                err.flush()?;
            }
            // Flushed per chunk: a bench that prints as it goes must read as
            // one here too, not arrive all at once when it exits.
            ServerMsg::Chunk { err: is_err, data } => {
                if is_err {
                    err.write_all(&data)?;
                    err.flush()?;
                } else if let Mode::Fetch(_) = mode {
                    // Under --message-format, cargo's stdout is the JSON. It is
                    // for us, not for the terminal.
                    records.feed(&data);
                } else {
                    out.write_all(&data)?;
                    out.flush()?;
                }
            }
            ServerMsg::Exit(c) => break c,
            ServerMsg::Error(e) => return Err(io::Error::other(e)),
            _ => return Err(io::Error::other("unexpected message during build")),
        }
    };

    // cargo has spoken. Its verdict stands, and there is nothing to fetch from a
    // build that didn't happen.
    let Mode::Fetch(here) = mode else {
        let _ = send(&mut w, &ClientMsg::Bye);
        return Ok(Built {
            code,
            exes: Vec::new(),
        });
    };
    if code != 0 {
        let _ = send(&mut w, &ClientMsg::Bye);
        return Ok(Built {
            code,
            exes: Vec::new(),
        });
    }

    // ---- fetch ----------------------------------------------------------
    let t = target.expect("a fetch implies a cross target");
    let mut exes = Vec::new();
    for exe in records.executables(here) {
        // The path cargo reports is absolute on the server, and the server will
        // only serve paths under this project's target dir. The triple is where
        // one becomes the other.
        let Some(rel) = rel_under_target(&exe, t) else {
            return Err(io::Error::other(format!(
                "cargo reported a binary outside the target dir: {exe}"
            )));
        };
        let dst = cwd.join("target").join("remote").join(
            rel.trim_start_matches(t)
                .trim_start_matches('/')
                .replace('/', MAIN_SEPARATOR_STR),
        );
        fetch(&mut r, &mut w, cwd, proj, &rel, &dst)?;
        exes.push(dst);
    }

    let _ = send(&mut w, &ClientMsg::Bye);
    Ok(Built { code, exes })
}

/// The path of `exe` relative to the project's target dir, which is the only
/// thing [`ClientMsg::Fetch`] will serve. `None` if it isn't under one.
fn rel_under_target(exe: &str, target: &str) -> Option<String> {
    // A Windows server reports backslashes; the wire only ever speaks forward.
    let exe = exe.replace('\\', "/");
    let at = exe.find(&format!("/{target}/"))?;
    let rel = exe[at + 1..].to_string();
    valid_rel(&rel).then_some(rel)
}

fn fetch<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    cwd: &Path,
    proj: &str,
    rel: &str,
    dst: &Path,
) -> io::Result<()> {
    send(
        w,
        &ClientMsg::Fetch {
            project: proj.into(),
            rel: rel.into(),
        },
    )?;

    let dir = dst.parent().unwrap_or(cwd);
    fs::create_dir_all(dir)?;
    let tmp = dst.with_extension("part");

    let mut wire = 0u64;
    let raw = {
        let file = BufWriter::with_capacity(CHUNK, fs::File::create(&tmp)?);
        let mut dec = zstd::stream::write::Decoder::new(file)?;
        let raw = loop {
            match recv::<ServerMsg, _>(r)? {
                ServerMsg::Data(d) => {
                    wire += d.len() as u64;
                    dec.write_all(&d)?;
                }
                ServerMsg::DataEnd { raw } => break raw,
                ServerMsg::Error(e) => {
                    let _ = fs::remove_file(&tmp);
                    return Err(io::Error::other(format!("fetch: {e}")));
                }
                _ => return Err(io::Error::other("unexpected message during fetch")),
            }
        };
        dec.flush()?;
        dec.into_inner().flush()?;
        raw
    };

    // rename last: a half-written exe must never look like a good one
    fs::rename(&tmp, dst)?;

    let ratio = if wire > 0 { raw as f64 / wire as f64 } else { 1.0 };
    eprintln!(
        "[rbuild] {} on the wire, {} on disk ({ratio:.1}x) -> {}",
        human(wire),
        human(raw),
        rel_to_cwd(cwd, dst).display(),
    );
    Ok(())
}

/// Cargo's `--message-format=json` stream, reassembled from wire chunks.
///
/// Cargo names every file it produced, hash and all, so nothing here has to
/// guess at a filename or know where a profile puts its output.
#[derive(Default)]
struct Json {
    /// A chunk boundary lands wherever the socket felt like it, which is rarely
    /// the end of a line.
    partial: Vec<u8>,
    made: Vec<Made>,
}

/// One executable cargo reported, and whether it is a harness.
struct Made {
    /// True for a binary built to be *run by* `cargo test` or `cargo bench`.
    /// The same bin target yields both: the program itself, and a harness with
    /// the test and bench functions linked in.
    harness: bool,
    path: String,
}

#[derive(Deserialize)]
struct Record {
    reason: String,
    target: Option<RecordTarget>,
    profile: Option<RecordProfile>,
    executable: Option<String>,
}

#[derive(Deserialize)]
struct RecordTarget {
    kind: Vec<String>,
}

#[derive(Deserialize)]
struct RecordProfile {
    test: bool,
}

impl Json {
    fn feed(&mut self, data: &[u8]) {
        self.partial.extend_from_slice(data);
        while let Some(nl) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=nl).collect();
            self.take(&line);
        }
    }

    fn take(&mut self, line: &[u8]) {
        let Ok(rec) = serde_json::from_slice::<Record>(line) else {
            return;
        };
        if rec.reason != "compiler-artifact" {
            return;
        }
        let (Some(path), Some(target)) = (rec.executable, rec.target) else {
            return;
        };
        // A build script is an executable cargo produced and nobody asked for.
        if target.kind.iter().any(|k| k == "custom-build") {
            return;
        }
        self.made.push(Made {
            harness: rec.profile.is_some_and(|p| p.test),
            path,
        });
    }

    /// The binaries `here` calls for.
    ///
    /// Building a bench or a test also builds the package's plain bins, because
    /// a harness may launch one through `CARGO_BIN_EXE`. Running those too would
    /// start the GUI in the middle of a benchmark, so the harness flag, not the
    /// target kind, decides.
    fn executables(&self, here: Local) -> Vec<String> {
        self.made
            .iter()
            .filter(|m| match here {
                Local::None => true,
                Local::One => !m.harness,
                Local::Every => m.harness,
            })
            .map(|m| m.path.clone())
            .collect()
    }
}

fn rel_to_cwd(cwd: &Path, p: &Path) -> PathBuf {
    p.strip_prefix(cwd).unwrap_or(p).to_path_buf()
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
        let Ok(modified) = md.modified() else {
            continue;
        };
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
    let mut key = PrivateKey::read_openssh_file(&path)
        .map_err(|e| io::Error::other(format!("reading {}: {e}", path.display())))?;
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
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)?;
    writeln!(f, "{host} {fp}")?;
    Ok(())
}

// ---- local fallback -----------------------------------------------------

/// With no server to build on, the command means what plain cargo would have
/// made of it, argv and all. `run`, `test` and `bench` build and run in one
/// step here, so nothing needs fetching.
fn local(sub: &str, args: &[String], exe_args: &[String]) -> ExitCode {
    let mut cmd = Command::new("cargo");
    cmd.arg(sub).args(args);
    if !exe_args.is_empty() {
        cmd.arg("--").args(exe_args);
    }
    match cmd.status() {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).min(255) as u8),
        Err(e) => die(&format!("cargo: {e}")),
    }
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
