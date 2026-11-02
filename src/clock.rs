// Minimal RFC 3339 UTC timestamps ("2026-10-30T10:00:00Z") without external
// crates. Used for config loadedAt echo (05 §5.3) and audit ts (02 §2.5).

use std::time::{SystemTime, UNIX_EPOCH};

/// Format the current wall clock as RFC 3339 UTC with second precision.
pub fn now_rfc3339() -> String {
    format_rfc3339(SystemTime::now())
}

pub fn format_rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's civil_from_days: days since 1970-01-01 → (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-10-30T10:00:00Z (spec 02 §2.3 example)
        let t = UNIX_EPOCH + Duration::from_secs(1_793_354_400);
        assert_eq!(format_rfc3339(t), "2026-10-30T10:00:00Z");
        // Leap-year day: 2024-02-29T12:00:00Z
        let t = UNIX_EPOCH + Duration::from_secs(1_709_208_000);
        assert_eq!(format_rfc3339(t), "2024-02-29T12:00:00Z");
    }
}
