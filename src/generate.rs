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

use chrono::prelude::*;
use crate::{
    expiry::{expiry_to_bytes, EXPIRY_SIZE},
    signature::compute_signature,
    HMACSHA256_BYTES,
};
use rand::{thread_rng, Rng};
use std::io::{self, Write};

pub(super) fn generate_token(secret: &[u8], expiry: DateTime<Utc>, nonce_size: usize) -> Vec<u8> {
    let mut nonce = vec![0; nonce_size];
    thread_rng().fill(nonce.as_mut_slice());
    let expiry = expiry_to_bytes(expiry);
    let signature_value = compute_signature(&nonce, &expiry, secret);

    let mut result = Vec::with_capacity(nonce_size + EXPIRY_SIZE + HMACSHA256_BYTES);
    result.write(&nonce).unwrap();
    result.write(&expiry).unwrap_or_else(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            panic!("The system clock is broken.");
        } else {
            unreachable!();
        }
    });
    result.write(&signature_value).unwrap();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_generate_token_with_far_past_expiry() {
        let expiry = DateTime::from_utc(NaiveDateTime::from_timestamp(i64::min_value(), 0), Utc);
        generate_token(&[], expiry, 32);
    }

    #[test]
    #[should_panic]
    fn test_generate_token_with_far_future_expiry() {
        let expiry = DateTime::from_utc(NaiveDateTime::from_timestamp(i64::max_value(), 0), Utc);
        generate_token(&[], expiry, 32);
    }
}
