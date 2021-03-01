// Copyright 2018 Future Science Research Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use chrono::prelude::*;
use std::io;

const NANOS_IN_SEC: i64 = 1_000_000_000;

pub(crate) const EXPIRY_SIZE: usize = 8;

fn timestamp_to_date_time(timestamp_nanos: i64) -> DateTime<Utc> {
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
    /// Write an expiry into the underlying write.
    ///
    /// # Errors
    ///
    /// If `expiry` is far future or far past value
    /// (before UNIX epoch or about 584 years later from UNIX epoch),
    /// this method returns an error with `io::ErrorKind::InvalidData`.
    /// That means the system clock used to compute the expiry is broken.
    ///
    /// Otherwise, when the underlying writer fails, this method returns the error.
    fn write_expiry(&mut self, expiry: DateTime<Utc>) -> io::Result<()> {
        let min = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        // If the expiry exceeds this instant, the timestamp overflows.
        let max = DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(
                i64::max_value() / NANOS_IN_SEC,
                (i64::max_value() % NANOS_IN_SEC) as u32,
            ),
            Utc,
        );
        if expiry < min || max < expiry {
            return Err(io::ErrorKind::InvalidData.into());
        }

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
    fn test_expiry_size() {
        let mut buf = Vec::new();
        let expiry = DateTime::parse_from_rfc3339("2018-11-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        buf.write_expiry(expiry).unwrap();
        assert_eq!(EXPIRY_SIZE, buf.len());
    }

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

    #[test]
    fn test_write_expiry_huge_absolute_value() {
        // based on erroneous token found by fuzz testing
        let bytes = b"\x80\x00\x00\x00\x31\x92\x6b\x23";
        let dt = bytes_to_expiry(bytes);

        let mut buf = Vec::new();
        match buf.write_expiry(dt) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            _ => panic!(),
        }
    }
}
