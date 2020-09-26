use crate::models::User;
use crate::session;
use crate::{ApiError, SessionSettings, UserDbConn};

use diesel::insert_into;
use rocket::http::{Cookie, Cookies, RawStr};
use rocket::request::Form;
use rocket::response::{Flash, Redirect};
use rocket::State;

use sodiumoxide::crypto::pwhash::{self, HashedPassword};

use crate::diesel::prelude::*;

/// `LoginInfo` describes the data needed to login and register.
#[derive(Debug, Clone, FromForm)]
pub struct LoginInfo<'r> {
    username: String,
    password: &'r RawStr,
}

/// `create_user` creates a user in the backend.
fn create_user(conn: &UserDbConn, name: String, password_hash: &[u8]) -> Result<User, ApiError> {
    use crate::schema::users::dsl::*;
    let db_conn = &conn.0;

    let uid = name.clone();
    if let Ok(pw) = String::from_utf8(password_hash.to_vec()) {
        if let Ok(rows) = insert_into(users)
            .values((username.eq(uid), password.eq(pw)))
            .execute(db_conn)
        {
            println!("Created {} users", rows);
        } else {
            println!("Failed to create user {}", name);
            return Err(ApiError::Internal);
        }
        println!("Created user {}", name);
        match fetch_user(conn, name) {
            Some(u) => Ok(u),
            None => {
                println!("Can't find user which was just created!");
                Err(ApiError::Internal)
            }
        }
    } else {
        println!("Failed to convert password into text");
        Err(ApiError::Internal)
    }
}

/// `fetch_user` fetches a user from the database.
pub fn fetch_user(conn: &UserDbConn, user: String) -> Option<User> {
    use crate::schema::users::dsl::*;
    let db_conn = &conn.0;

    match users.filter(username.eq(user)).load::<User>(db_conn) {
        Ok(mut user) => {
            let len = user.len();
            if len == 1 {
                return user.pop();
            } else if len > 1 {
                println!("Found {} users, but there should only be one!", len);
            }
            return None;
        }
        Err(e) => {
            println!("Failed to find user in database: {}", e);
            return None;
        }
    }
}

/// In the future, `is_password_secure` is supposed to check if complexity is enough
fn is_password_secure(password: String) -> bool {
    password.len() > 12
}

#[post(
    "/login",
    data = "<login_info>",
    format = "application/x-www-form-urlencoded"
)]
pub fn login(
    conn: UserDbConn,
    session_conf: State<SessionSettings>,
    login_info: Form<LoginInfo>,
    mut cookies: Cookies,
) -> Result<Flash<Redirect>, ApiError> {
    let username = &login_info.username;
    let user = fetch_user(&conn, username.to_string());
    match user {
        Some(user) => {
            if let Some(pwh) = HashedPassword::from_slice(user.get_password().as_bytes()) {
                if pwhash::pwhash_verify(&pwh, &login_info.password.as_bytes()) {
                    if let Ok(st) = session::create_session_token(
                        &conn,
                        &session_conf,
                        username.into(),
                        vec!["user".to_string()],
                    ) {
                        cookies.add_private(Cookie::new("session_token", st));
                        Ok(Flash::success(Redirect::to("/"), "Successfully logged in!"))
                    } else {
                        println!("Failed to create session token");
                        Err(ApiError::Internal)
                    }
                } else {
                    println!("Password verification failed");
                    Err(ApiError::InvalidLogin)
                }
            } else {
                println!("Failed to retrieve credentials");
                Err(ApiError::Internal)
            }
        }
        None => {
            println!("User not found!");
            Err(ApiError::InvalidLogin)
        }
    }
}

#[post(
    "/register",
    data = "<login_info>",
    format = "application/x-www-form-urlencoded"
)]
pub fn register(
    conn: UserDbConn,
    session_conf: State<SessionSettings>,
    login_info: Form<LoginInfo>,
    mut cookies: Cookies,
) -> Result<Flash<Redirect>, ApiError> {
    let username = &login_info.username;
    let pw = &login_info.password;
    match fetch_user(&conn, username.to_string()) {
        Some(_) => {
            println!("Can't register user, name is already taken");
            return Err(ApiError::AlreadyExists);
        }
        None => {
            if is_password_secure(pw.to_string()) {
                if let Ok(pwh) = pwhash::pwhash(
                    login_info.password.as_bytes(),
                    pwhash::OPSLIMIT_INTERACTIVE,
                    pwhash::MEMLIMIT_INTERACTIVE,
                ) {
                    if let Ok(user) = create_user(&conn, username.to_string(), pwh.as_ref()) {
                        println!("User '{}' created", user.get_username());
                        if let Ok(st) = session::create_session_token(
                            &conn,
                            &session_conf,
                            username.to_string(),
                            vec!["user".to_string()],
                        ) {
                            cookies.add_private(Cookie::new("session_token", st));
                            Ok(Flash::success(Redirect::to("/"), "Successfully logged in!"))
                        } else {
                            println!("Failed to create session token");
                            Err(ApiError::Internal)
                        }
                    } else {
                        println!("Failed to create user '{}'", username);
                        Err(ApiError::Internal)
                    }
                } else {
                    println!("Failed to create password hash");
                    Err(ApiError::Internal)
                }
            } else {
                println!("Password is not secure enough");
                Err(ApiError::WeakPassword)
            }
        }
    }
}

#[post("/logout")]
pub fn logout(conn: UserDbConn, mut cookies: Cookies) -> Flash<Redirect> {
    session::expire_session_token(
        &conn,
        cookies
            .get_private("session_token")
            .and_then(|cookie| cookie.value().parse().ok())
            .unwrap_or_default(),
    );
    cookies.remove_private(Cookie::named("session_token"));
    Flash::success(Redirect::to("/"), "Successfully logged out.")
}
