#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde_derive;
extern crate branca;

use rocket::fairing::AdHoc;
use thiserror::Error;

#[database("sqlite_db")]
pub struct UserDbConn(diesel::SqliteConnection);

pub struct SessionSettings(String, i64);

pub mod models;
pub mod schema;
pub mod session;
mod user;

#[get("/")]
fn test(_sess: &session::Session) -> &'static str {
    "SUCCESS!"
}

#[get("/", rank = 2)]
fn index() -> &'static str {
    "Hello, world!"
}

fn main() {
    rocket::ignite()
        .mount(
            "/",
            routes![test, index, user::login, user::register, user::logout],
        )
        .attach(UserDbConn::fairing())
        .attach(AdHoc::on_attach("Session Token Secret", |rocket| {
            let session_token_secret_key = rocket
                .config()
                .get_str("session_token_secret_key")
                .unwrap()
                .to_string();
            let session_duration: i64 = rocket.config().get_int("session_duration").unwrap_or(0);

            Ok(rocket.manage(SessionSettings(session_token_secret_key, session_duration)))
        }))
        .launch();
}

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Internal error")]
    Internal,
    #[error("Token is expired")]
    ExpiredToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("No token found")]
    NoToken,
    #[error("Invalid login information provided")]
    InvalidLogin,
    #[error("Username already exists")]
    AlreadyExists,
    #[error("Password is not strong enough")]
    WeakPassword,
    #[error("User not found")]
    NotFound,
}
