//! Lexical command recognition only. This helper never selects a profile,
//! normalizes a spelling, or consults the filesystem/PATH.

pub const MAX_EXECUTABLE_BYTES: usize = 4096;

/// A bare name or normalized absolute POSIX path, preserving case and Unicode.
/// Wildcards, spaces, and backslashes are literal filename characters.
pub fn basename(spelling: &str) -> Option<&str> {
    if spelling.is_empty()
        || spelling.len() > MAX_EXECUTABLE_BYTES
        || spelling.bytes().any(|b| b.is_ascii_control())
    {
        return None;
    }
    if !spelling.contains('/') {
        return (!matches!(spelling, "." | "..")).then_some(spelling);
    }
    let path = spelling.strip_prefix('/')?;
    if path.split('/').any(|p| matches!(p, "" | "." | "..")) {
        return None;
    }
    path.rsplit('/').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_only() {
        for (spelling, name) in [
            ("tool", "tool"),
            ("/opt/tools/tool", "tool"),
            ("/a b/工具", "工具"),
            (r"c:\tool", r"c:\tool"),
            ("/opt/*", "*"),
        ] {
            assert_eq!(basename(spelling), Some(name));
        }
        for spelling in [
            "",
            ".",
            "..",
            "/",
            "./tool",
            "a/tool",
            "//tool",
            "/a//tool",
            "/a/./tool",
            "/a/../tool",
            "/tool/",
            "to\nol",
            "to\u{7f}ol",
            "to\0ol",
        ] {
            assert_eq!(basename(spelling), None, "{spelling:?}");
        }
        assert!(basename(&"é".repeat(2048)).is_some());
        assert!(basename(&format!("{}a", "é".repeat(2048))).is_none());
    }
}
