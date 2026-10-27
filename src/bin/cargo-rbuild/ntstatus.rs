//! Descriptions of the NTSTATUS exit codes a failed Windows program ends with:
//! [`describe_failure`].

/// What the exit code `code` says went wrong, when it is an NTSTATUS error: a
/// program the loader refused to start, or one Windows ended.
///
/// `None` for a code outside NTSTATUS's error range, as an ordinary exit code
/// is, and for Ctrl-C, which the user already knows about.
///
/// Cut to a byte, an NTSTATUS error reads as a plausible small exit code, as
/// `STATUS_DLL_NOT_FOUND` becomes 53, so it is said out loud instead.
pub fn describe_failure(code: i32) -> Option<String> {
    const CONTROL_C_EXIT: u32 = 0xC000_013A;

    let status = code as u32;
    if status < 0xC000_0000 || status == CONTROL_C_EXIT {
        return None;
    }

    Some(match status {
        0xC000_0135 => format!(
            "did not start: a DLL it imports was not found ({status:#010x}, STATUS_DLL_NOT_FOUND)"
        ),
        0xC000_0139 => format!(
            "did not start: a function it imports was not found in its DLL \
             ({status:#010x}, STATUS_ENTRYPOINT_NOT_FOUND)"
        ),
        0xC000_0138 => format!(
            "did not start: an ordinal it imports was not found in its DLL \
             ({status:#010x}, STATUS_ORDINAL_NOT_FOUND)"
        ),
        0xC000_007B => format!(
            "did not start: it or a DLL it imports is not an image for this machine \
             ({status:#010x}, STATUS_INVALID_IMAGE_FORMAT)"
        ),
        0xC000_0142 => format!(
            "did not start: a DLL it imports failed to initialize \
             ({status:#010x}, STATUS_DLL_INIT_FAILED)"
        ),
        0xC000_0005 => format!("exited with {status:#010x}, STATUS_ACCESS_VIOLATION"),
        0xC000_00FD => format!("exited with {status:#010x}, STATUS_STACK_OVERFLOW"),
        0xC000_0409 => format!("exited with {status:#010x}, STATUS_STACK_BUFFER_OVERRUN"),
        _ => format!("exited with {status:#010x}"),
    })
}
