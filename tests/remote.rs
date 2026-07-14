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

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("probe")
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
    /// `CARGO_MANIFEST_DIR` must point at.
    fn remote_project(&self) -> PathBuf {
        self.dir.join("src").join("probe")
    }

    fn client(&self, args: &[&str]) -> Run {
        let mut cmd = Command::new(CLIENT);
        cmd.args(args)
            .current_dir(fixture())
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
    let mut cmd = Command::new(CLIENT);
    cmd.args(args)
        .current_dir(fixture())
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
    let remote = rig.remote_project();
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
    let fetched = fixture().join("target").join("remote");
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
