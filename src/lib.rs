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
        target: String,
    },
    /// Fetch an artifact. Server restricts this to the targets tree.
    Fetch {
        project: String,
        rel: String,
    },
    Bye,
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
    DataEnd,
    Error(String),
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
