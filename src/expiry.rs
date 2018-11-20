use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use chrono::prelude::*;
use std::io;

pub(crate) const EXPIRY_SIZE: usize = 8;

fn timestamp_to_date_time(timestamp_nanos: i64) -> DateTime<Utc> {
    const NANOS_IN_SEC: i64 = 1_000_000_000;

    let rem = timestamp_nanos % NANOS_IN_SEC;
    let naive = if timestamp_nanos >= 0 {
        NaiveDateTime::from_timestamp(timestamp_nanos / NANOS_IN_SEC, rem as u32)
    } else {
        if rem == 0 {
            NaiveDateTime::from_timestamp(timestamp_nanos / NANOS_IN_SEC, 0)
        } else {
            NaiveDateTime::from_timestamp(
                timestamp_nanos / NANOS_IN_SEC - 1,
                (NANOS_IN_SEC + rem) as u32,
            )
        }
    };
    DateTime::<Utc>::from_utc(naive, Utc)
}

pub(crate) trait WriteExpiry: io::Write {
    fn write_expiry(&mut self, expiry: DateTime<Utc>) -> io::Result<()> {
        self.write_i64::<BigEndian>(expiry.timestamp_nanos())
    }
}

impl<T: io::Write> WriteExpiry for T {}

pub(crate) fn bytes_to_expiry(bytes: &[u8]) -> DateTime<Utc> {
    assert!(bytes.len() == EXPIRY_SIZE);
    timestamp_to_date_time(BigEndian::read_i64(bytes))
}

pub(crate) fn expiry_to_bytes(expiry: DateTime<Utc>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(EXPIRY_SIZE);
    buf.write_expiry(expiry).unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_to_date_time() {
        // confirm that the function doesn't panic
        timestamp_to_date_time(i64::max_value());
        timestamp_to_date_time(-1234567890);
        timestamp_to_date_time(0);
        timestamp_to_date_time(1234567890);
        timestamp_to_date_time(i64::max_value());
    }

    #[test]
    fn test_bytes_to_expiry() {
        assert_eq!(
            bytes_to_expiry(&[0; 8]),
            DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z").unwrap()
        );
    }

    #[test]
    fn test_write_expiry() {
        let dt = DateTime::parse_from_rfc3339("1971-01-01T00:00:02.000000003Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut buf = Vec::new();
        buf.write_expiry(dt).unwrap();
        // (1 * 365*24*60*60 + 2) * 10^9 + 3 = 0x0070_09d3_a4d8_9403
        assert_eq!(buf, b"\x00\x70\x09\xd3\xa4\xd8\x94\x03");
    }

    // UNIX Epochで表した現在時刻の絶対値が大きい（約584年）場合、
    // ナノ秒のタイムスタンプを取得するとき、オーバーフローする。
    #[test]
    #[ignore]
    fn test_write_expiry_huge_absolute_value() {
        // based on erroneous token found by fuzz testing
        let bytes = b"\x80\x00\x00\x00\x31\x92\x6b\x23";
        let dt = bytes_to_expiry(bytes);

        let mut buf = Vec::new();
        // should not panic
        buf.write_expiry(dt).unwrap();
    }
}
