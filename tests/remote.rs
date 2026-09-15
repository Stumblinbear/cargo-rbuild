//! End-to-end tests over a real rbuild-server, on a loopback port.
//!
//! Both halves of the protocol run here: the test spawns `rbuild-server` with a
//! throwaway host key and a throwaway source tree, then drives `cargo-rbuild`
//! against it with `tests/fixtures/probe` as the project. Nothing touches the
//! real homelab, `~/.ssh`, or `~/.rbuild`.
//!
//! To drive the same rig by hand, from the repo root:
//!
//! ```text
//! cargo build --release
//! ssh-keygen -t ed25519 -N "" -f /tmp/rig/key
//! RBUILD_AUTHORIZED_KEYS="$(cat /tmp/rig/key.pub)" RBUILD_HOST_KEY=/tmp/rig/host_key \
//!   RBUILD_SRC=/tmp/rig/src RBUILD_TARGETS=/tmp/rig/targets RBUILD_BIND=127.0.0.1:7878 \
//!   ./target/release/rbuild-server &
//! cd tests/fixtures/probe
//! RBUILD_HOST=127.0.0.1 RBUILD_KEY=/tmp/rig/key ../../../target/release/cargo-rbuild \
//!   run --remote --bin alpha -- 7 hello
//! ```

use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CLIENT: &str = env!("CARGO_BIN_EXE_cargo-rbuild");
const SERVER: &str = env!("CARGO_BIN_EXE_rbuild-server");

/// A cold dependency-free build, a run, and three 400 ms ticks fit in this many
/// times over. Anything slower is a hang, not a slow machine.
const BUDGET: Duration = Duration::from_secs(240);

fn real_home() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    PathBuf::from(home)
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A line of a client's output and how long after launch it arrived.
struct Line {
    at: Duration,
    text: String,
}

struct Run {
    code: i32,
    out: Vec<Line>,
    err: Vec<Line>,
}

impl Run {
    fn stdout(&self) -> String {
        join(&self.out)
    }

    fn stderr(&self) -> String {
        join(&self.err)
    }

    /// How long the run spent producing lines matching `needle`. Zero means they
    /// all landed at once, which is what a buffered-to-the-end stream looks like.
    fn spread(&self, needle: &str) -> Duration {
        let hits: Vec<Duration> = self
            .out
            .iter()
            .chain(&self.err)
            .filter(|l| l.text.contains(needle))
            .map(|l| l.at)
            .collect();
        match (hits.iter().min(), hits.iter().max()) {
            (Some(a), Some(b)) => *b - *a,
            _ => Duration::ZERO,
        }
    }
}

fn join(lines: &[Line]) -> String {
    lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A server, its keys and its trees, all under one temp dir that goes away with
/// the test.
struct Rig {
    dir: PathBuf,
    port: u16,
    child: Child,
}

impl Rig {
    fn start(name: &str) -> Rig {
        let dir = std::env::temp_dir().join(format!("rbuild-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("keygen");
        key.write_openssh_file(&dir.join("key"), ssh_key::LineEnding::LF)
            .expect("write key");
        let authorized = key.public_key().to_openssh().expect("pubkey");

        // Claim a free port, then hand the number to the server. The gap between
        // the drop and the bind is the price of not teaching the server to
        // report its own port.
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("free port")
            .local_addr()
            .expect("addr")
            .port();

        let child = Command::new(SERVER)
            .env("RBUILD_AUTHORIZED_KEYS", authorized)
            .env("RBUILD_HOST_KEY", dir.join("host_key"))
            .env("RBUILD_SRC", dir.join("src"))
            .env("RBUILD_TARGETS", dir.join("targets"))
            .env("RBUILD_BIND", format!("127.0.0.1:{port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");

        let rig = Rig { dir, port, child };
        rig.wait_until_listening();
        rig
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("rbuild-server never listened on {}", self.port);
    }

    /// The project tree as the server sees it, which is what the probe's baked
    /// `CARGO_MANIFEST_DIR` must point at. `project` is the sync root's own
    /// dirname — the workspace root's for a workspace, the crate's own for a
    /// standalone package.
    fn remote_project(&self, project: &str) -> PathBuf {
        self.dir.join("src").join(project)
    }

    /// Runs the client from the `probe` fixture, as every single-package test
    /// does.
    fn client(&self, args: &[&str]) -> Run {
        self.client_in(&fixture("probe"), args)
    }

    /// Runs the client from an arbitrary directory — a workspace root or one
    /// of its members.
    fn client_in(&self, dir: &Path, args: &[&str]) -> Run {
        let mut cmd = Command::new(CLIENT);
        cmd.args(args)
            .current_dir(dir)
            .env("RBUILD_HOST", "127.0.0.1")
            .env("RBUILD_PORT", self.port.to_string())
            .env("RBUILD_KEY", self.dir.join("key"))
            // The client pins host keys under the home dir, and a fresh server
            // key every run would otherwise trip the real known_hosts.
            .env("USERPROFILE", &self.dir)
            .env("HOME", &self.dir);

        // Moving the home dir moved rustup's, and the client runs `cargo
        // metadata`. Point the toolchain back at the real one.
        let home = real_home();
        if std::env::var_os("RUSTUP_HOME").is_none() {
            cmd.env("RUSTUP_HOME", home.join(".rustup"));
        }
        if std::env::var_os("CARGO_HOME").is_none() {
            cmd.env("CARGO_HOME", home.join(".cargo"));
        }
        run(cmd)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A client that never reaches a server, so it keeps the real home: the checks
/// it makes before connecting shell out to `cargo metadata`, and rustup finds
/// its toolchain through the home dir.
fn offline(args: &[&str]) -> Run {
    offline_in(&fixture("probe"), args)
}

/// Same as [`offline`], from an arbitrary directory.
fn offline_in(dir: &Path, args: &[&str]) -> Run {
    let mut cmd = Command::new(CLIENT);
    cmd.args(args)
        .current_dir(dir)
        .env("RBUILD_HOST", "127.0.0.1")
        .env("RBUILD_PORT", "1"); // refused instantly if anything does try to connect
    run(cmd)
}

fn run(mut cmd: Command) -> Run {
    let t0 = Instant::now();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn client");

    // Drained on threads: a full pipe would otherwise stall the child before it
    // could exit, and the timeout below would blame the wrong thing.
    let out = drain(child.stdout.take().expect("stdout"), t0);
    let err = drain(child.stderr.take().expect("stderr"), t0);

    let deadline = Instant::now() + BUDGET;
    let code = loop {
        match child.try_wait().expect("wait") {
            Some(s) => break s.code().unwrap_or(-1),
            None if Instant::now() > deadline => {
                let _ = child.kill();
                panic!("client did not finish within {BUDGET:?}");
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    };

    Run {
        code,
        out: out.join().expect("stdout thread"),
        err: err.join().expect("stderr thread"),
    }
}

fn drain<R: Read + Send + 'static>(r: R, t0: Instant) -> JoinHandle<Vec<Line>> {
    thread::spawn(move || {
        BufReader::new(r)
            .lines()
            .map_while(Result::ok)
            .map(|text| Line {
                at: t0.elapsed(),
                text,
            })
            .collect()
    })
}

#[test]
fn remote_run_streams_argv_and_exit_code() {
    let rig = Rig::start("run");
    let r = rig.client(&["run", "--remote", "--bin", "alpha", "--", "7", "hello"]);

    assert_eq!(r.code, 7, "the program's exit code is the command's\n{}", r.stderr());

    let out = r.stdout();
    assert!(out.contains("PROBE=alpha"), "wrong target ran:\n{out}");
    assert!(
        out.contains(r#"ARGV=["7", "hello"]"#),
        "argv did not reach the program:\n{out}"
    );

    // Proof the binary really was built on the server: the manifest dir it baked
    // in at compile time is the server's copy of the tree, not this one.
    let remote = rig.remote_project("probe");
    assert!(
        out.contains(&format!("MANIFEST_DIR={}", remote.display())),
        "expected a manifest dir under {}:\n{out}",
        remote.display()
    );

    // Each stream comes back on its own, not folded together.
    let err = r.stderr();
    assert!(out.contains("stdout tick 2"), "stdout missing:\n{out}");
    assert!(err.contains("stderr tick 2"), "stderr missing:\n{err}");
    assert!(!out.contains("stderr tick"), "stderr leaked into stdout:\n{out}");
    assert!(!err.contains("stdout tick"), "stdout leaked into stderr:\n{err}");

    // The ticks are 400 ms apart at the source. Arriving together would mean the
    // output was held until the program exited.
    let spread = r.spread("tick");
    assert!(
        spread >= Duration::from_millis(300),
        "output was not streamed: all ticks landed within {spread:?}"
    );
}

#[test]
fn remote_bench_runs_and_passes_argv() {
    let rig = Rig::start("bench");
    let r = rig.client(&["bench", "--remote", "--bench", "probebench", "--", "0"]);

    assert_eq!(r.code, 0, "bench should pass\n{}", r.stderr());
    let out = r.stdout();
    assert!(out.contains("PROBE=probebench"), "wrong target ran:\n{out}");
    // cargo adds this itself, and a harness that treats it as a positional arg
    // will try to open a fixture called "--bench".
    assert!(out.contains("--bench"), "cargo's own arg went missing:\n{out}");
    assert!(out.contains(r#""0""#), "argv did not reach the bench:\n{out}");
}

#[test]
fn remote_example_panic_fails_the_command() {
    let rig = Rig::start("panic");
    let r = rig.client(&["run", "--remote", "--example", "sample", "--", "panic"]);

    assert_eq!(r.code, 101, "a panic must fail the command");
    assert!(
        r.stderr().contains("probe panicked on request"),
        "the panic message never came back:\n{}",
        r.stderr()
    );
}

/// Without --remote, a bench is built on the server and run here, off the file
/// cargo named. Nothing reconstructs the hashed filename.
#[test]
fn bench_fetches_the_hashed_binary_and_runs_it_here() {
    let rig = Rig::start("fetch");
    let r = rig.client(&["bench", "--bench", "probebench", "--", "5"]);

    assert_eq!(r.code, 5, "the bench's exit code is the command's\n{}", r.stderr());

    let out = r.stdout();
    assert!(out.contains("PROBE=probebench"), "wrong target ran:\n{out}");
    assert!(out.contains(r#""5""#), "argv did not reach the bench:\n{out}");
    // cargo appends this to a bench's argv, and so must we.
    assert!(out.contains("--bench"), "the bench flag went missing:\n{out}");

    // Ran here, off a fetched file, not on the server.
    let err = r.stderr();
    let fetched = fixture("probe").join("target").join("remote");
    assert!(
        err.contains(&format!("running {}", fetched.display())),
        "the bench did not run from the fetched binary:\n{err}"
    );
    // The name cargo hashes is the name we fetched.
    assert!(
        err.contains("deps") && err.contains("probebench-"),
        "expected a hashed deps/ filename:\n{err}"
    );
}

#[test]
fn example_fetches_and_runs_here() {
    let rig = Rig::start("example");
    let r = rig.client(&["run", "--example", "sample", "--", "3"]);

    assert_eq!(r.code, 3, "{}", r.stderr());
    assert!(r.stdout().contains("PROBE=sample"), "{}", r.stdout());
    assert!(
        r.stderr().contains("examples"),
        "an example should come back under examples/:\n{}",
        r.stderr()
    );
}

/// `test` rides the identical path: cargo names the test binaries, we fetch and
/// run them. Doctests are the one thing that cannot come along.
#[test]
fn test_fetches_every_test_binary_and_runs_them_here() {
    let rig = Rig::start("test");
    let r = rig.client(&["test"]);

    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(
        r.stdout().contains("running 0 tests"),
        "the fetched test harness never ran:\n{}",
        r.stdout()
    );
    assert!(
        r.stderr().contains("doctests stay on the server"),
        "the doctest gap must be said out loud:\n{}",
        r.stderr()
    );
}

#[test]
fn ambiguity_is_refused() {
    // --remote runs a program; a check doesn't have one.
    let r = offline(&["check", "--remote"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr().contains("--native"), "{}", r.stderr());

    // Two bins and no default-run: rbuild must not pick one.
    let r = offline(&["run"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr().contains("default-run"), "{}", r.stderr());

    // A typo is cheaper to catch before the build than after it.
    let r = offline(&["run", "--example", "nosuch"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr().contains("no example target"), "{}", r.stderr());
}

/// An explicitly native build is server-only: a transport failure must never
/// silently turn it into a local cargo invocation.
#[test]
fn native_build_does_not_fall_back_when_the_server_is_unreachable() {
    let r = offline(&["check", "--native"]);

    assert_eq!(
        r.code,
        1,
        "an explicit native build must fail remotely\n{}",
        r.stderr()
    );
    assert!(
        r.stderr().contains("remote build:"),
        "the remote failure was not reported:\n{}",
        r.stderr()
    );
}

// ---- workspaces -----------------------------------------------------------
//
// `wsprobe` is a real two-crate workspace: a virtual root with an inherited
// edition, `wscore` (lib + integration test `it`), `wsbin` (bin + integration
// test `smoke`). It exercises what `probe` can't: syncing the workspace root
// rather than whatever directory the command was typed from, and resolving
// which package(s) a command line actually selects.

fn ws_root() -> PathBuf {
    fixture("wsprobe")
}

fn ws_member(name: &str) -> PathBuf {
    ws_root().join("crates").join(name)
}

/// Failure mode A: a bare `cargo rbuild test` from the workspace root used to
/// die with "cwd is a workspace root, not a package" before it ever reached a
/// server — `plan`/`select` run locally, so `offline` alone proves it either
/// way.
#[test]
fn workspace_root_bare_subcommand_is_no_longer_refused() {
    let r = offline_in(&ws_root(), &["test"]);

    assert!(
        !r.stderr().contains("workspace root, not a package"),
        "the deleted error came back:\n{}",
        r.stderr()
    );
    // No server on the other end of an offline run, so reaching this point
    // fell back to a real local `cargo test` — proof `plan`/`select` let the
    // command through instead of dying first.
    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(
        r.stdout().contains("quadruples"),
        "wscore's own integration test never ran:\n{}",
        r.stdout()
    );
}

/// Failure mode B: syncing only the member subtree left the server's copy
/// without the root manifest `wscore`'s inherited `edition` depends on.
#[test]
fn member_dir_build_gets_the_synced_workspace_root() {
    let rig = Rig::start("ws-member");
    let r = rig.client_in(&ws_member("wscore"), &["check"]);

    assert!(
        !r.stderr().contains("failed to find a workspace root"),
        "the root manifest never made it to the server:\n{}",
        r.stderr()
    );
    assert_eq!(r.code, 0, "{}", r.stderr());
}

/// From the root, `-p` still picks out one member — and the server actually
/// runs it, proving the sync carried both crates over and the flag reached
/// cargo intact.
#[test]
fn dash_p_at_root_runs_the_named_member() {
    let rig = Rig::start("ws-dash-p");
    let r = rig.client_in(&ws_root(), &["run", "--remote", "-p", "wsbin"]);

    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(r.stdout().contains("WSBIN running"), "{}", r.stdout());
}

/// Recursively copies a fixture tree into a scratch dir, so a test that must
/// corrupt a manifest never touches the shared fixture other tests read
/// concurrently.
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir");
    for entry in std::fs::read_dir(src).expect("read_dir") {
        let entry = entry.expect("dir entry");
        // Other tests build inside the shared fixture concurrently; its
        // target/ is neither wanted here nor safe to copy mid-write.
        if entry.file_name() == "target" {
            continue;
        }
        let ty = entry.file_type().expect("file type");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).expect("copy file");
        }
    }
}

/// A crate deleted locally left its directory on the server: the push removed
/// its files one by one and nothing removed the directory they emptied, so a
/// workspace listing its members as `crates/*` failed its next manifest load
/// there on a member with no `Cargo.toml`.
#[test]
fn a_deleted_crate_takes_its_directory_off_the_server() {
    let scratch = std::env::temp_dir().join(format!(
        "rbuild-scratch-deleted-crate-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    copy_tree(&ws_root(), &scratch);
    let root_manifest = scratch.join("Cargo.toml");
    let original = std::fs::read_to_string(&root_manifest).expect("read root manifest");
    std::fs::write(
        &root_manifest,
        original.replace(
            "members = [\"crates/wscore\", \"crates/wsbin\"]",
            "members = [\"crates/*\"]",
        ),
    )
    .expect("glob the members");
    let extra = scratch.join("crates").join("wsextra");
    std::fs::create_dir_all(extra.join("src")).expect("mkdir wsextra");
    std::fs::write(
        extra.join("Cargo.toml"),
        "[package]\nname = \"wsextra\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
    )
    .expect("write wsextra manifest");
    std::fs::write(extra.join("src").join("lib.rs"), "pub fn extra() {}\n").expect("write lib");

    let rig = Rig::start("ws-deleted-crate");
    let before = rig.client_in(&scratch, &["check"]);
    assert_eq!(before.code, 0, "{}", before.stderr());

    std::fs::remove_dir_all(&extra).expect("delete wsextra");
    let after = rig.client_in(&scratch, &["check"]);

    let project = scratch.file_name().and_then(|s| s.to_str()).expect("scratch name");
    let remote_extra = rig.remote_project(project).join("crates").join("wsextra");
    let kept = remote_extra.exists();
    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(
        after.code,
        0,
        "the server kept the deleted crate's directory:
{}",
        after.stderr()
    );
    assert!(!kept, "{} is still on the server", remote_extra.display());
}

/// A syntax-broken manifest is a real failure, not a "no manifest here" that
/// falls back to the pre-workspace guess: `Meta::load` must surface cargo's
/// own parse diagnostic and die, not silently swallow it into `Ok(None)`.
#[test]
fn corrupt_manifest_dies_loudly_instead_of_falling_back() {
    let scratch = std::env::temp_dir().join(format!(
        "rbuild-scratch-corrupt-offline-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    copy_tree(&ws_root(), &scratch);
    let root_manifest = scratch.join("Cargo.toml");
    let original = std::fs::read_to_string(&root_manifest).expect("read root manifest");
    std::fs::write(&root_manifest, format!("{original}\nnot valid toml [[[\n"))
        .expect("corrupt root manifest");

    let member = scratch.join("crates").join("wscore");
    let r = offline_in(&member, &["check"]);

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(r.code, 1, "{}", r.stderr());
    assert!(
        r.stderr().contains("failed to parse manifest"),
        "cargo's own parse diagnostic never surfaced:\n{}",
        r.stderr()
    );
}

/// The failure mode `Meta::load` must not resurrect, shown against a real
/// server: pre-fix, `Ok(None)` on the parse error fell back to guessing `cwd`
/// as the sync root, so only `wscore`'s own subtree synced (never the root
/// manifest), and the server died on an unrelated "failed to find a workspace
/// root" — cargo's real parse diagnostic never appeared anywhere, and the
/// sync went ahead at all. Post-fix, rbuild dies here, before ever syncing.
#[test]
fn corrupt_manifest_is_caught_before_a_partial_sync_reaches_the_server() {
    let scratch = std::env::temp_dir().join(format!(
        "rbuild-scratch-corrupt-online-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    copy_tree(&ws_root(), &scratch);
    let root_manifest = scratch.join("Cargo.toml");
    let original = std::fs::read_to_string(&root_manifest).expect("read root manifest");
    std::fs::write(&root_manifest, format!("{original}\nnot valid toml [[[\n"))
        .expect("corrupt root manifest");

    let rig = Rig::start("corrupt-manifest-live");
    let member = scratch.join("crates").join("wscore");
    let r = rig.client_in(&member, &["check"]);

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(r.code, 1, "{}", r.stderr());
    assert!(
        r.stderr().contains("failed to parse manifest"),
        "cargo's own parse diagnostic never surfaced:\n{}",
        r.stderr()
    );
    assert!(
        !r.stderr().contains("[rbuild] sync:"),
        "a partial subtree sync reached the server instead of dying first:\n{}",
        r.stderr()
    );
}

/// `run` in a bin-less package (empty `--bin`/`--example`/... select, not just
/// "more than one") must die cleanly, not index an empty Vec.
#[test]
fn run_in_binless_package_is_a_clean_error() {
    let r = offline_in(&ws_member("wscore"), &["run"]);
    assert_eq!(r.code, 1, "{}", r.stderr());
    assert!(
        r.stderr().contains("no executable target selected to run"),
        "{}",
        r.stderr()
    );
}

/// A `-p` naming no real package is caught here, not after a build.
#[test]
fn unknown_dash_p_lists_the_real_packages() {
    let r = offline_in(&ws_root(), &["build", "-p", "nosuchpkg"]);

    assert_eq!(r.code, 1);
    let err = r.stderr();
    assert!(err.contains("no package named"), "{err}");
    assert!(err.contains("wscore") && err.contains("wsbin"), "{err}");
}

/// `at_package` (the member dir cwd names) must never preempt an explicit
/// `-p`/`--workspace` on the command line — only the injection it drives.
/// From `wscore`'s own directory, `-p wsbin --test smoke` must select wsbin,
/// not get silently steered back to wscore's target list.
#[test]
fn explicit_dash_p_overrides_at_package_from_a_member_dir() {
    let r = offline_in(&ws_member("wscore"), &["build", "-p", "wsbin", "--test", "smoke"]);
    assert_eq!(r.code, 0, "{}", r.stderr());
}

/// Same priority bug, the typo-check angle: `-p nosuchpkg` from a member dir
/// must still be validated by rbuild itself, not silently forwarded to cargo
/// because `at_package` ate the selection first.
#[test]
fn explicit_dash_p_typo_from_member_dir_is_still_caught() {
    let r = offline_in(&ws_member("wscore"), &["build", "-p", "nosuchpkg"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr().contains("no package named"), "{}", r.stderr());
}

/// `-p=name` (the `=`-joined attached form) must parse the same as `-p name`,
/// not swallow the `=` into the package name.
#[test]
fn dash_p_equals_form_parses_the_name_without_the_equals() {
    let r = offline_in(&ws_member("wscore"), &["build", "-p=wsbin", "--test", "smoke"]);
    assert_eq!(r.code, 0, "{}", r.stderr());
}

/// `-pname` (cargo's attached short-flag form) must count as explicit
/// selection too, or `at_package`'s injection doubles up alongside it.
#[test]
fn attached_dash_p_form_counts_as_explicit_selection() {
    let r = offline_in(&ws_member("wscore"), &["build", "-pwsbin", "--test", "smoke"]);
    assert_eq!(r.code, 0, "{}", r.stderr());
}

/// `--all` is cargo's deprecated spelling of `--workspace`.
#[test]
fn dash_dash_all_selects_the_whole_workspace() {
    let r = offline_in(&ws_root(), &["build", "--all", "--test", "nosuch"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr().contains("Available: it, smoke"), "{}", r.stderr());
}

/// The typo-check's "Available" list is scoped to whichever package set the
/// command line actually selected: `-p wscore` alone never offers `wsbin`'s
/// targets, `--workspace` (and the bare default, which resolves to the same
/// set in this fixture) offers both.
#[test]
fn typo_check_lists_only_the_selected_packages() {
    let one = offline_in(&ws_root(), &["build", "-p", "wscore", "--test", "nosuch"]);
    assert_eq!(one.code, 1);
    assert!(one.stderr().contains("Available: it"), "{}", one.stderr());
    // "Available: it" is also a prefix of the wrongly-scoped "Available: it,
    // smoke" — assert the exclusion directly, not just the substring match.
    assert!(!one.stderr().contains("smoke"), "{}", one.stderr());

    let other = offline_in(&ws_root(), &["build", "-p", "wsbin", "--test", "nosuch"]);
    assert_eq!(other.code, 1);
    assert!(other.stderr().contains("Available: smoke"), "{}", other.stderr());

    let all = offline_in(&ws_root(), &["build", "--workspace", "--test", "nosuch"]);
    assert_eq!(all.code, 1);
    assert!(all.stderr().contains("Available: it, smoke"), "{}", all.stderr());

    let bare = offline_in(&ws_root(), &["build", "--test", "nosuch"]);
    assert_eq!(bare.code, 1);
    assert!(bare.stderr().contains("Available: it, smoke"), "{}", bare.stderr());
}

/// A scratch copy of the probe fixture with two files held back by two
/// different rules, so an `--include` test never writes into the fixture the
/// rest of the suite is reading.
///
/// `git init` because .gitignore only applies inside a repository. `.ignore`
/// answers to no git at all, which is why it is the second rule.
fn ignoring_scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rbuild-inc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy_tree(&fixture("probe"), &dir);

    std::fs::write(dir.join(".gitignore"), "by-gitignore.txt\n").expect("write .gitignore");
    std::fs::write(dir.join(".ignore"), "by-dot-ignore.txt\n").expect("write .ignore");
    std::fs::write(dir.join("by-gitignore.txt"), b"not source")
        .expect("write the git-ignored file");
    std::fs::write(dir.join("by-dot-ignore.txt"), b"not source")
        .expect("write the dot-ignored file");

    let init = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&dir)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed in {}",
        dir.display()
    );

    dir
}

/// The name the server files a scratch tree under: the sync root's own dirname.
fn project_of(dir: &Path) -> String {
    dir.file_name()
        .and_then(|s| s.to_str())
        .expect("scratch name")
        .to_string()
}

/// `--include` is the only way an ignored file reaches the server, whichever
/// rule holds it back, and it says what *this run* syncs: the run that forgets
/// it takes the file back off, the same way deleting it locally would.
#[test]
fn ignored_files_reach_the_server_only_when_included() {
    let scratch = ignoring_scratch("only-when-included");
    let project = project_of(&scratch);

    let rig = Rig::start("include");
    let by_git = rig.remote_project(&project).join("by-gitignore.txt");
    let by_dot = rig.remote_project(&project).join("by-dot-ignore.txt");

    let without = rig.client_in(&scratch, &["check"]);
    let synced_without = (by_git.exists(), by_dot.exists());

    let with = rig.client_in(
        &scratch,
        &[
            "check",
            "--include",
            "by-gitignore.txt",
            "--include",
            "by-dot-ignore.txt",
        ],
    );
    let synced_with = (by_git.exists(), by_dot.exists());

    let forgotten = rig.client_in(&scratch, &["check"]);
    let kept_after = (by_git.exists(), by_dot.exists());

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(without.code, 0, "{}", without.stderr());
    assert_eq!(with.code, 0, "{}", with.stderr());
    assert_eq!(forgotten.code, 0, "{}", forgotten.stderr());

    assert_eq!(
        synced_without,
        (false, false),
        "the ignore rules should have held both back"
    );
    assert_eq!(
        synced_with,
        (true, true),
        "--include did not send them:\n{}",
        with.stderr()
    );
    assert_eq!(
        kept_after,
        (false, false),
        "a run without the flag left them on the server"
    );
}

/// The attached form, and proof the glob is rbuild's own: cargo has no
/// `--include`, so a forwarded one would fail the build instead.
#[test]
fn include_takes_the_attached_form_and_never_reaches_cargo() {
    let scratch = ignoring_scratch("attached");
    let project = project_of(&scratch);

    let rig = Rig::start("include-attached");
    let r = rig.client_in(&scratch, &["check", "--include=**/by-*.txt"]);
    let synced = rig
        .remote_project(&project)
        .join("by-gitignore.txt")
        .exists();

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(synced, "the glob matched nothing:\n{}", r.stderr());
}

/// `.git` and `target` stay behind whatever a glob names: the most permissive
/// one there is would otherwise push the whole history and the build output at
/// a builder other people share.
#[test]
fn git_and_target_stay_behind_under_a_permissive_glob() {
    let scratch = ignoring_scratch("permissive");
    let project = project_of(&scratch);
    std::fs::create_dir_all(scratch.join("target")).expect("mkdir target");
    std::fs::write(scratch.join("target").join("junk.bin"), b"build output").expect("write junk");

    let rig = Rig::start("include-permissive");
    let r = rig.client_in(&scratch, &["check", "--include=**"]);
    let there = rig.remote_project(&project);
    let reached_ignored = there.join("by-gitignore.txt").exists();
    let sent_git = there.join(".git").exists();
    let sent_target = there.join("target").exists();

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(
        reached_ignored,
        "the glob reached nothing the ignore rules held back:\n{}",
        r.stderr()
    );
    assert!(!sent_git, ".git went to the server");
    assert!(!sent_target, "target went to the server");
}

/// A glob that names nothing looks exactly like one that worked, and the run
/// that swallows it builds against a file that never arrived.
#[test]
fn a_glob_that_matches_nothing_says_so() {
    let scratch = ignoring_scratch("no-match");

    let rig = Rig::start("include-no-match");
    let r = rig.client_in(&scratch, &["check", "--include", "by-gitignroe.txt"]);

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(
        r.stderr()
            .contains("--include matched nothing: by-gitignroe.txt"),
        "{}",
        r.stderr()
    );
}

/// A glob is required, and a malformed one is caught before anything connects.
#[test]
fn include_without_a_usable_glob_is_a_usage_error() {
    let bare = offline(&["check", "--include"]);
    assert_eq!(bare.code, 1);
    assert!(
        bare.stderr().contains("--include needs a glob"),
        "{}",
        bare.stderr()
    );

    let flag_shaped = offline(&["check", "--include", "--remote"]);
    assert_eq!(flag_shaped.code, 1);
    assert!(
        flag_shaped.stderr().contains("--include needs a glob"),
        "{}",
        flag_shaped.stderr()
    );

    let malformed = offline(&["check", "--include=a[b"]);
    assert_eq!(malformed.code, 1);
    assert!(
        malformed.stderr().contains("--include"),
        "{}",
        malformed.stderr()
    );
}

/// The removal `--include` promises holds for every later run, `--full`
/// included: a full re-upload is a repair, and a secret this run doesn't name
/// still comes off.
#[test]
fn a_full_run_without_the_flag_still_takes_the_included_file_off() {
    let scratch = ignoring_scratch("full");
    let project = project_of(&scratch);

    let rig = Rig::start("include-full");
    let there = rig.remote_project(&project).join("by-gitignore.txt");

    let with = rig.client_in(&scratch, &["check", "--include", "by-gitignore.txt"]);
    let synced = there.exists();

    let forgotten = rig.client_in(&scratch, &["check", "--full"]);
    let kept = there.exists();

    let _ = std::fs::remove_dir_all(&scratch);

    assert_eq!(with.code, 0, "{}", with.stderr());
    assert_eq!(forgotten.code, 0, "{}", forgotten.stderr());

    assert!(synced, "--include did not send it:\n{}", with.stderr());
    assert!(!kept, "a --full run without the flag left it on the server");
}

/// Past `--` the words belong to the program, so a flag spelled like one of
/// rbuild's own stays in its argv.
#[test]
fn rbuild_flags_after_the_dash_dash_belong_to_the_program() {
    let rig = Rig::start("argv-flags");
    let r = rig.client(&[
        "run",
        "--remote",
        "--bin",
        "alpha",
        "--",
        "0",
        "--full",
        "--include",
    ]);

    assert_eq!(r.code, 0, "{}", r.stderr());
    assert!(
        r.stdout().contains(r#"ARGV=["0", "--full", "--include"]"#),
        "rbuild ate the program's own arguments:\n{}",
        r.stdout()
    );
}
