extern crate actix_web;
extern crate base64;
extern crate chrono;
extern crate csrf_token;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate hex;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use actix_web::{
    actix, error::UrlencodedError, server, App, AsyncResponder, HttpMessage, HttpRequest,
    HttpResponse, Responder, ResponseError,
};
use chrono::Duration;
use csrf_token::{CsrfTokenError, CsrfTokenGenerator};
use futures::Future;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;

#[derive(Debug, Fail)]
enum ApplicationError {
    #[fail(display = "{}", _0)]
    CsrfTokenError(CsrfTokenError),

    #[fail(display = "malformed request parameter")]
    RequestParamError,
}

impl From<CsrfTokenError> for ApplicationError {
    fn from(error: CsrfTokenError) -> ApplicationError {
        ApplicationError::CsrfTokenError(error)
    }
}

impl From<UrlencodedError> for ApplicationError {
    fn from(_: UrlencodedError) -> ApplicationError {
        ApplicationError::RequestParamError
    }
}

impl ResponseError for ApplicationError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApplicationError::CsrfTokenError(CsrfTokenError::TokenInvalid) => {
                HttpResponse::Forbidden().body("Error: CSRF token invalid")
            }
            ApplicationError::CsrfTokenError(CsrfTokenError::TokenExpired) => {
                HttpResponse::Forbidden().body("Error: CSRF token expired")
            }
            ApplicationError::RequestParamError => HttpResponse::BadRequest().finish(),
        }
    }
}

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
        .from_err::<ApplicationError>()
        .and_then(move |params| match hex::decode(&params.csrf_token) {
            Ok(token) => {
                generator.verify(&token)?;
                Ok(HttpResponse::Ok().body("Posted message: ".to_string() + &params.message))
            }
            Err(_) => Err(CsrfTokenError::TokenInvalid.into()),
        }).responder()
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
