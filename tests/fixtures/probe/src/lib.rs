//! The body every probe target shares. Each target only names itself.

use std::io::Write;
use std::time::Duration;

/// Announces `who`, its baked manifest dir and its argv, then writes to both
/// streams three times, 400 ms apart, and exits.
///
/// The first non-flag argument steers the ending: `panic` panics, an integer is
/// the exit code, anything else exits 0. That is what lets one binary stand in
/// for a passing bench, a failing bench, and a crashing one.
pub fn probe(who: &str) -> ! {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    println!("PROBE={who}");
    // Baked at compile time, so this names the tree the binary was compiled in.
    // The tests read it to tell a remotely-built binary from a locally-built one.
    println!("MANIFEST_DIR={}", env!("CARGO_MANIFEST_DIR"));
    println!("ARGV={argv:?}");

    // cargo hands a `harness = false` bench a literal `--bench`, so a positional
    // argument is anything that doesn't look like a flag.
    let words: Vec<&str> = argv
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();

    if words.first() == Some(&"panic") {
        panic!("probe panicked on request");
    }

    // Spread out in time: output that arrives in one burst at the end was
    // buffered somewhere it shouldn't have been.
    for i in 0..3 {
        println!("stdout tick {i}");
        eprintln!("stderr tick {i}");
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        std::thread::sleep(Duration::from_millis(400));
    }

    let code: i32 = words.first().and_then(|a| a.parse().ok()).unwrap_or(0);
    eprintln!("exiting with {code}");
    std::process::exit(code);
}
