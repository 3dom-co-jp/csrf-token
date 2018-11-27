use chrono::prelude::*;
use crypto::{digest::Digest, sha2::Sha256};
use digest::compute_digest;
use expiry::{expiry_to_bytes, EXPIRY_SIZE};
use rand::{thread_rng, Rng};
use std::io::{self, Write};

pub(super) fn generate_token(
    secret: &[u8],
    expiry: DateTime<Utc>,
    nonce_size: usize,
    digest: &mut Sha256,
) -> Vec<u8> {
    let mut nonce = vec![0; nonce_size];
    thread_rng().fill(nonce.as_mut_slice());
    let expiry = expiry_to_bytes(expiry);
    let digest_value = compute_digest(digest, &nonce, &expiry, secret);

    let mut result = Vec::with_capacity(nonce_size + EXPIRY_SIZE + digest.output_bytes());
    result.write(&nonce).unwrap();
    result.write(&expiry).unwrap_or_else(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            panic!("The system clock is broken.");
        } else {
            unreachable!();
        }
    });
    result.write(&digest_value).unwrap();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_generate_token_with_far_past_expiry() {
        let expiry = DateTime::from_utc(NaiveDateTime::from_timestamp(i64::min_value(), 0), Utc);
        generate_token(&[], expiry, 32, &mut Sha256::new());
    }

    #[test]
    #[should_panic]
    fn test_generate_token_with_far_future_expiry() {
        let expiry = DateTime::from_utc(NaiveDateTime::from_timestamp(i64::max_value(), 0), Utc);
        generate_token(&[], expiry, 32, &mut Sha256::new());
    }
}
