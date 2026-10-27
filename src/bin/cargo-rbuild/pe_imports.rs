//! The DLLs a Windows PE image imports: [`imported_dlls`].

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// The DLL names in the import table of the PE image at `path`, in table order,
/// as the image spells them.
///
/// A delay-loaded DLL, which the loader resolves at its first call rather than
/// before the program starts, is not listed.
///
/// # Errors
///
/// Fails with [`io::ErrorKind::InvalidData`] on a file that is not a PE image,
/// and with the read's own error on one cut short. Either error names `path`.
pub fn imported_dlls(path: &Path) -> io::Result<Vec<String>> {
    let mut image = Image {
        file: File::open(path)?,
    };
    image
        .imports()
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// A PE image open on disk.
struct Image {
    // Read a field at a time: a DLL can run to hundreds of megabytes, and the
    // import table needs only its headers and a few names.
    file: File,
}

/// Where a section's bytes sit in the image's address space and in the file.
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

impl Image {
    fn imports(&mut self) -> io::Result<Vec<String>> {
        if self.bytes::<2>(0)? != *b"MZ" {
            return Err(invalid("expected an MZ header"));
        }
        let pe = u64::from(self.u32(0x3c)?);
        if self.bytes::<4>(pe)? != *b"PE\0\0" {
            return Err(invalid("expected a PE signature"));
        }

        // The COFF file header, then the optional header, whose layout the
        // magic picks: PE32 or PE32+.
        let coff = pe + 4;
        let section_count = self.u16(coff + 2)?;
        let optional_size = u64::from(self.u16(coff + 16)?);
        let optional = coff + 20;
        let (directory_count, directories) = match self.u16(optional)? {
            0x10b => (optional + 92, optional + 96),
            0x20b => (optional + 108, optional + 112),
            magic => {
                return Err(invalid(&format!(
                    "unknown optional header magic {magic:#x}"
                )))
            }
        };

        // Data directory 1 is the import table. An image importing nothing may
        // have no entry for it at all.
        if self.u32(directory_count)? < 2 {
            return Ok(Vec::new());
        }
        let table = self.u32(directories + 8)?;
        if table == 0 {
            return Ok(Vec::new());
        }

        let sections_at = optional + optional_size;
        let sections = (0..u64::from(section_count))
            .map(|i| {
                let at = sections_at + i * 40;
                Ok(Section {
                    virtual_size: self.u32(at + 8)?,
                    virtual_address: self.u32(at + 12)?,
                    raw_size: self.u32(at + 16)?,
                    raw_offset: self.u32(at + 20)?,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;

        // One 20-byte descriptor per DLL, the name's address at offset 12, and
        // a zeroed descriptor to end the table.
        let mut at = file_offset(&sections, table)?;
        let mut names = Vec::new();
        loop {
            let name = self.u32(at + 12)?;
            if name == 0 {
                break;
            }
            names.push(self.c_string(file_offset(&sections, name)?)?);
            at += 20;
        }
        Ok(names)
    }

    fn bytes<const N: usize>(&mut self, at: u64) -> io::Result<[u8; N]> {
        let mut buf = [0u8; N];
        self.file.seek(SeekFrom::Start(at))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn u16(&mut self, at: u64) -> io::Result<u16> {
        self.bytes(at).map(u16::from_le_bytes)
    }

    fn u32(&mut self, at: u64) -> io::Result<u32> {
        self.bytes(at).map(u32::from_le_bytes)
    }

    /// The NUL-terminated UTF-8 string at `at`.
    ///
    /// One with no NUL in its first 256 bytes is refused: a DLL name is a file
    /// name, and no path component runs that long.
    fn c_string(&mut self, at: u64) -> io::Result<String> {
        const MAX: usize = 256;

        self.file.seek(SeekFrom::Start(at))?;
        let mut buf = Vec::with_capacity(MAX);
        (&mut self.file).take(MAX as u64).read_to_end(&mut buf)?;

        let end = buf
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| invalid("an imported DLL name has no terminator"))?;
        String::from_utf8(buf[..end].to_vec())
            .map_err(|_| invalid("an imported DLL name is not ASCII"))
    }
}

/// The file offset of the image address `rva`, or `InvalidData` when no
/// section maps it.
fn file_offset(sections: &[Section], rva: u32) -> io::Result<u64> {
    sections
        .iter()
        .find(|s| {
            let size = s.virtual_size.max(s.raw_size);
            rva >= s.virtual_address && rva - s.virtual_address < size
        })
        .map(|s| u64::from(s.raw_offset) + u64::from(rva - s.virtual_address))
        .ok_or_else(|| invalid(&format!("address {rva:#x} is in no section")))
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE32+ image of headers and one section, `.idata`, mapped at 0x2000
    /// and stored at 0x200: so every address the table holds differs from
    /// its file offset, as in a linked image.
    fn image_importing(names: &[&str]) -> Vec<u8> {
        const PE: usize = 0x80;
        const OPTIONAL: usize = PE + 24;
        const OPTIONAL_SIZE: usize = 112 + 16 * 8;
        const SECTIONS: usize = OPTIONAL + OPTIONAL_SIZE;
        const RAW: usize = 0x200;
        const RVA: u32 = 0x2000;

        let mut idata = vec![0u8; 20 * (names.len() + 1)];
        for (i, name) in names.iter().enumerate() {
            let name_rva = RVA + idata.len() as u32;
            idata[i * 20 + 12..i * 20 + 16].copy_from_slice(&name_rva.to_le_bytes());
            idata.extend_from_slice(name.as_bytes());
            idata.push(0);
        }

        let mut img = vec![0u8; RAW];
        let put = |img: &mut Vec<u8>, at: usize, bytes: &[u8]| {
            img[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut img, 0, b"MZ");
        put(&mut img, 0x3c, &(PE as u32).to_le_bytes());
        put(&mut img, PE, b"PE\0\0");
        put(&mut img, PE + 4 + 2, &1u16.to_le_bytes());
        put(&mut img, PE + 4 + 16, &(OPTIONAL_SIZE as u16).to_le_bytes());
        put(&mut img, OPTIONAL, &0x20bu16.to_le_bytes());
        put(&mut img, OPTIONAL + 108, &16u32.to_le_bytes());
        put(&mut img, OPTIONAL + 112 + 8, &RVA.to_le_bytes());
        put(
            &mut img,
            OPTIONAL + 112 + 12,
            &(idata.len() as u32).to_le_bytes(),
        );
        put(&mut img, SECTIONS, b".idata\0\0");
        put(&mut img, SECTIONS + 8, &(idata.len() as u32).to_le_bytes());
        put(&mut img, SECTIONS + 12, &RVA.to_le_bytes());
        put(&mut img, SECTIONS + 16, &(idata.len() as u32).to_le_bytes());
        put(&mut img, SECTIONS + 20, &(RAW as u32).to_le_bytes());
        img.extend_from_slice(&idata);
        img
    }

    fn written(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rbuild-pe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write image");
        path
    }

    #[test]
    fn lists_the_import_table_in_order() {
        let path = written(
            "imports.dll",
            &image_importing(&["std-0123456789abcdef.dll", "KERNEL32.dll"]),
        );

        let names = imported_dlls(&path).expect("parse");
        let _ = std::fs::remove_file(&path);

        assert_eq!(names, ["std-0123456789abcdef.dll", "KERNEL32.dll"]);
    }

    #[test]
    fn refuses_a_file_that_is_not_an_image() {
        let path = written("not-an-image.dll", b"#!/bin/sh\necho hi\n");

        let err = imported_dlls(&path).expect_err("a script is not a PE image");
        let _ = std::fs::remove_file(&path);

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
