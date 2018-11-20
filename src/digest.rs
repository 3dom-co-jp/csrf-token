use crypto::{digest::Digest, sha2::Sha256};

pub(crate) fn compute_digest(
    digest: &mut Sha256,
    nonce: &[u8],
    expiry: &[u8],
    secret: &[u8],
) -> Vec<u8> {
    digest.input(nonce);
    digest.input(expiry);
    digest.input(secret);
    let mut result = vec![0; digest.output_bytes()];
    digest.result(&mut result);
    result
}
