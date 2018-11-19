extern crate actix_web;
extern crate base64;
extern crate chrono;
extern crate crypto;
extern crate csrf_token;
extern crate futures;
extern crate hex;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use actix_web::{
    actix, error::Error as ActixWebError, server, App, AsyncResponder, HttpMessage, HttpRequest,
    HttpResponse, Responder,
};
use chrono::Duration;
use csrf_token::{CsrfTokenError, CsrfTokenGenerator};
use futures::Future;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;

const FORM_TEMPLATE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/form.html"));

type State = Arc<CsrfTokenGenerator>;

fn form(req: &HttpRequest<State>) -> impl Responder {
    let generator = req.state();
    let token = hex::encode(&generator.generate());
    HttpResponse::Ok()
        .content_type("text/html")
        .body(FORM_TEMPLATE.replace("{{csrf-token}}", &token))
}

#[derive(Deserialize)]
struct PostParams {
    csrf_token: String,
    message: String,
}

fn post(req: &HttpRequest<State>) -> impl Responder {
    let generator = req.state().clone();
    req.urlencoded::<PostParams>()
        .from_err::<ActixWebError>()
        .and_then(move |params| match hex::decode(&params.csrf_token) {
            Ok(token) => Ok(response_for_post(&params.message, &token, &generator)),
            Err(_) => Ok(HttpResponse::Forbidden().body("Error: CSRF token invalid")),
        }).responder()
}

fn response_for_post(message: &str, token: &[u8], generator: &CsrfTokenGenerator) -> HttpResponse {
    match generator.verify(token) {
        Ok(()) => HttpResponse::Ok().body("Posted message: ".to_string() + message),
        Err(CsrfTokenError::TokenInvalid) => {
            HttpResponse::Forbidden().body("Error: CSRF token invalid")
        }
        Err(CsrfTokenError::TokenExpired) => {
            HttpResponse::Forbidden().body("Error: CSRF token expired")
        }
    }
}

fn main() {
    let mut buf = String::new();
    BufReader::new(File::open("examples/secret").expect("secret key file doesn't exist"))
        .read_to_string(&mut buf)
        .expect("failed to read secret key file");
    let secret = hex::decode(buf.trim()).expect("failed to hex decode secret key file");

    let generator = Arc::new(CsrfTokenGenerator::new(secret, Duration::hours(1)));

    let sys = actix::System::new("example");
    server::new(move || {
        App::with_state(generator.clone())
            .resource("/", |r| r.get().f(form))
            .resource("/post", |r| r.post().f(post))
    }).bind("localhost:8080")
    .expect("port 8080 unavailable")
    .start();

    println!("Access http://localhost:8080/");
    sys.run();
}
