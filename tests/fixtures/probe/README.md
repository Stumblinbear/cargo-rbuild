# probe

The crate `tests/remote.rs` builds and runs over a real `rbuild-server`. It is a
standalone workspace, so the parent's `cargo build` and `cargo test` never see
it; only the tests, and the sync, ever reach in here.

Its shape is the point. Each target is one line calling `probe::probe`, and
between them they cover every axis the wire protocol can silently get wrong:

| axis | what covers it |
| --- | --- |
| `--bin` selection, and the refusal when two bins have no `default-run` | `alpha`, `beta` |
| `--example` | `sample` |
| `--bench`, whose filename cargo hashes and whose argv cargo appends `--bench` to | `probebench` (`harness = false`) |
| a bench build also producing the package's plain bins, which must not be run | `alpha`, `beta` |
| stdout and stderr arriving separately | every target writes to both |
| argv reaching the program | every target prints its own |
| a nonzero exit, and a panic | first argument: an integer is the exit code, `panic` panics |
| output streaming instead of arriving in one burst | the ticks are 400 ms apart |
| whether a binary was built here or on the server | it prints its baked `MANIFEST_DIR` |

## By hand

`cargo test` does all of this on a loopback port, but to watch it:

```sh
cargo build --release
mkdir -p /tmp/rig && ssh-keygen -t ed25519 -N "" -f /tmp/rig/key

RBUILD_AUTHORIZED_KEYS="$(cat /tmp/rig/key.pub)" \
RBUILD_HOST_KEY=/tmp/rig/host_key \
RBUILD_SRC=/tmp/rig/src \
RBUILD_TARGETS=/tmp/rig/targets \
RBUILD_BIND=127.0.0.1:7878 \
  ./target/release/rbuild-server &

cd tests/fixtures/probe
RBUILD_HOST=127.0.0.1 RBUILD_KEY=/tmp/rig/key \
  ../../../target/release/cargo-rbuild run --remote --bin alpha -- 7 hello
```

That should print the ticks as they happen, report a `MANIFEST_DIR` under
`/tmp/rig/src/probe` rather than this directory, and exit 7.

`RBUILD_PORT` moves the client off 7878 if something already holds it.
