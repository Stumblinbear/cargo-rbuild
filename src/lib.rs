//! Wire protocol shared by client and server.
//!
//! Framing: `u32` little-endian length, then a bincode-encoded message.
//! Bulk file bodies are NOT framed — after a `Push`, the client writes each
//! file's bytes back to back, and the server reads exactly `size` bytes per
//! header. Framing every 4 KB source file individually would be pure overhead.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const PORT: u16 = 7878;
pub const NAMESPACE: &str = "rbuild@local";
pub const CHUNK: usize = 1 << 20;

/// Guard against a hostile or confused peer asking us to allocate a gigabyte.
const MAX_FRAME: u32 = 16 << 20;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileHeader {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
}

impl FileHeader {
    /// The size and time the quick check compares this file by.
    pub fn stamp(&self) -> FileStamp {
        FileStamp {
            size: self.size,
            mtime: self.mtime,
        }
    }
}

/// A file's size and modification time, the pair rsync's quick check compares
/// to tell whether a copy is current.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct FileStamp {
    pub size: u64,
    /// Whole seconds since the Unix epoch.
    pub mtime: i64,
}

impl FileStamp {
    /// The stamp of the file `md` describes.
    ///
    /// A modification time the platform cannot report, or one before the
    /// epoch, reads as 0.
    pub fn of(md: &std::fs::Metadata) -> FileStamp {
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        FileStamp {
            size: md.len(),
            mtime,
        }
    }

    /// Whether the quick check counts the two stamped files as the same: their
    /// sizes are equal and their times agree.
    ///
    /// Times within a second agree, because NTFS and ext4 disagree about
    /// granularity.
    pub fn is_same(&self, other: &FileStamp) -> bool {
        self.size == other.size && (self.mtime - other.mtime).abs() <= 1
    }
}

/// Converts a [`FileStamp::mtime`] back to the time it stands for.
///
/// A negative `mtime` converts to the epoch, as [`FileStamp::of`] stamps a
/// time before the epoch as 0.
///
/// # Panics
///
/// If the platform's `SystemTime` cannot represent the time.
pub fn mtime_to_system_time(mtime: i64) -> std::time::SystemTime {
    let secs = u64::try_from(mtime).unwrap_or(0);
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMsg {
    /// SSHSIG over the server's nonce, proving we hold the private key.
    Auth {
        pubkey: String,
        sig_pem: String,
    },
    /// "Tell me what you already have for this project."
    Manifest {
        project: String,
    },
    /// Deletions, then headers. Raw bodies follow immediately, in header order.
    Push {
        project: String,
        deletes: Vec<String>,
        files: Vec<FileHeader>,
    },
    Build {
        project: String,
        subcommand: String,
        args: Vec<String>,
        /// `None` => native host build, run in the container.
        target: Option<String>,
        /// Args after `--` (criterion filters, example argv).
        trailing: Vec<String>,
    },
    /// Fetch an artifact. Server restricts this to the targets tree.
    Fetch {
        project: String,
        rel: String,
    },
    Bye,
    /// Run cargo and reply with `Chunk`s, then `Exit`.
    ///
    /// Unlike [`ClientMsg::Build`], the two output streams stay apart, so the
    /// caller can read `--message-format=json` records off stdout while
    /// diagnostics still reach a terminal. A `None` target builds for the
    /// server's own platform, which is the only way `run`, `test` and `bench`
    /// can execute anything there.
    Cargo {
        project: String,
        subcommand: String,
        args: Vec<String>,
        target: Option<String>,
        /// Args after `--`: the program's own argv, or its harness's.
        trailing: Vec<String>,
        /// `CARGO_TERM_COLOR` for the server's cargo, resolved by the client,
        /// since only the client can see whether its output is a terminal.
        /// `None` leaves colour to cargo's own `auto` and `term.color`.
        color: Option<String>,
    },
    /// Fetch a DLL a fetched binary imports, from the first of `dirs` holding
    /// it, else from the toolchain's library dir for `target`.
    ///
    /// The reply is [`ServerMsg::LibraryMissing`] when neither holds it,
    /// [`ServerMsg::LibraryUnchanged`] when `have` matches the server's copy, or
    /// [`ServerMsg::Library`] and the body as `Data` frames and a `DataEnd`. An
    /// invalid path, or a file the server cannot open, gets
    /// [`ServerMsg::Error`].
    ///
    /// A server older than this message drops the connection on it.
    FetchLibrary {
        project: String,
        /// The triple the binary was built for.
        target: String,
        /// Relative to the project's target tree, as [`ClientMsg::Fetch`]'s
        /// `rel` is.
        dirs: Vec<String>,
        /// The DLL's file name as the binary imports it: one path component.
        name: String,
        /// The stamp of the client's copy, if it has one.
        have: Option<FileStamp>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMsg {
    Hello {
        nonce: Vec<u8>,
        host_pubkey: String,
    },
    AuthOk,
    Manifest(Vec<FileHeader>),
    PushOk {
        received: u64,
    },
    /// A chunk of merged cargo stdout+stderr, streamed live.
    Output(Vec<u8>),
    Exit(i32),
    Data(Vec<u8>),
    DataEnd {
        raw: u64,
    },
    Error(String),
    /// A chunk of an executing program's output, tagged with the stream it came
    /// from so the client can reproduce the split on its own stdout and stderr.
    Chunk {
        err: bool,
        data: Vec<u8>,
    },
    /// Neither the searched dirs nor the toolchain's library dir holds the
    /// library.
    LibraryMissing,
    /// The client's copy of the library matches the server's by the quick check.
    LibraryUnchanged,
    /// The library's body follows, as `Data` frames and a `DataEnd`.
    Library {
        /// The server's copy's [`FileStamp::mtime`], for the client to stamp
        /// its copy with so the next quick check matches.
        mtime: i64,
    },
}

impl ServerMsg {
    /// The name of this message's variant, as `LibraryMissing`, for an error
    /// about a reply that came out of turn.
    pub fn variant_name(&self) -> &'static str {
        match self {
            ServerMsg::Hello { .. } => "Hello",
            ServerMsg::AuthOk => "AuthOk",
            ServerMsg::Manifest(_) => "Manifest",
            ServerMsg::PushOk { .. } => "PushOk",
            ServerMsg::Output(_) => "Output",
            ServerMsg::Exit(_) => "Exit",
            ServerMsg::Data(_) => "Data",
            ServerMsg::DataEnd { .. } => "DataEnd",
            ServerMsg::Error(_) => "Error",
            ServerMsg::Chunk { .. } => "Chunk",
            ServerMsg::LibraryMissing => "LibraryMissing",
            ServerMsg::LibraryUnchanged => "LibraryUnchanged",
            ServerMsg::Library { .. } => "Library",
        }
    }
}

pub fn send<T: Serialize, W: Write>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = bincode::serialize(msg).map_err(io::Error::other)?;
    if body.len() as u64 > MAX_FRAME as u64 {
        return Err(io::Error::other("frame too large"));
    }
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn recv<T: for<'de> Deserialize<'de>, R: Read>(r: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    bincode::deserialize(&body).map_err(io::Error::other)
}

/// A project name becomes a path component on the server. Anything that could
/// escape `/src` or `/targets` is rejected outright rather than sanitised —
/// there is no legitimate reason for a slash to be in here.
pub fn valid_project(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != ".."
        && s != "."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Same idea for relative paths inside a project.
pub fn valid_rel(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 4096
        && !s.starts_with('/')
        && !s.contains('\\')
        && !s.contains('\0')
        && s.split('/').all(|c| !c.is_empty() && c != "..")
}
