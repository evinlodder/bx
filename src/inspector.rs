//! Live data inspector: every numeric interpretation of the bytes at the
//! cursor, in the spirit of 010's inspector panel. No `:mark` required.

use crate::buffer::FileBuffer;

/// `(label, value)` rows describing the up-to-8 bytes at `cursor`.
pub fn lines(buf: &FileBuffer, cursor: u64) -> Vec<(String, String)> {
    let b = buf.get_range(cursor, 8);
    let mut out = vec![("offset".into(), format!("0x{cursor:X} ({cursor})"))];
    if b.is_empty() {
        out.push(("byte".into(), "<EOF>".into()));
        return out;
    }

    let b0 = b[0];
    let ch = if (0x20..0x7f).contains(&b0) {
        (b0 as char).to_string()
    } else {
        "·".into()
    };
    out.push(("hex".into(), format!("0x{b0:02X}")));
    out.push(("binary".into(), format!("0b{b0:08b}")));
    out.push(("octal".into(), format!("0o{b0:03o}")));
    out.push(("ascii".into(), ch));
    out.push(("int8".into(), format!("{}", b0 as i8)));
    out.push(("uint8".into(), format!("{b0}")));

    if b.len() >= 2 {
        let le = u16::from_le_bytes([b[0], b[1]]);
        let be = u16::from_be_bytes([b[0], b[1]]);
        out.push(("int16 LE".into(), format!("{}", le as i16)));
        out.push(("uint16 LE".into(), format!("{le}")));
        out.push(("int16 BE".into(), format!("{}", be as i16)));
        out.push(("uint16 BE".into(), format!("{be}")));
    }
    if b.len() >= 4 {
        let arr: [u8; 4] = b[..4].try_into().unwrap();
        let le = u32::from_le_bytes(arr);
        let be = u32::from_be_bytes(arr);
        out.push(("int32 LE".into(), format!("{}", le as i32)));
        out.push(("uint32 LE".into(), format!("{le}")));
        out.push(("int32 BE".into(), format!("{}", be as i32)));
        out.push(("uint32 BE".into(), format!("{be}")));
        out.push(("float32 LE".into(), format!("{}", f32::from_le_bytes(arr))));
        out.push(("float32 BE".into(), format!("{}", f32::from_be_bytes(arr))));
        out.push(("time_t LE".into(), unix_time(le)));
    }
    if b.len() >= 8 {
        let arr: [u8; 8] = b[..8].try_into().unwrap();
        let le = u64::from_le_bytes(arr);
        let be = u64::from_be_bytes(arr);
        out.push(("int64 LE".into(), format!("{}", le as i64)));
        out.push(("uint64 LE".into(), format!("{le}")));
        out.push(("int64 BE".into(), format!("{}", be as i64)));
        out.push(("uint64 BE".into(), format!("{be}")));
        out.push(("float64 LE".into(), format!("{}", f64::from_le_bytes(arr))));
        out.push(("float64 BE".into(), format!("{}", f64::from_be_bytes(arr))));
    }
    out
}

/// Format a 32-bit Unix timestamp as a UTC datetime.
fn unix_time(secs: u32) -> String {
    let days = secs as i64 / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(unix_time(0), "1970-01-01 00:00:00Z");
        // 1234567890 == 2009-02-13 23:31:30 UTC
        assert_eq!(unix_time(1_234_567_890), "2009-02-13 23:31:30Z");
    }
}
