#[macro_use]
extern crate afl;
extern crate chrono;
extern crate csrf_token;

use chrono::Duration;
use csrf_token::CsrfTokenGenerator;

fn main() {
    let secret = b"0123456789abcedf0123456789abcdef".to_vec();
    let generator = CsrfTokenGenerator::new(secret, Duration::days(1));

    fuzz!(|data: &[u8]| {
        let _ = generator.verify(data);
    });
}
