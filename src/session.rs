use crate::models::SessionToken;
use crate::user;
use crate::{ApiError, SessionSettings, UserDbConn};
use branca::Branca;
use chrono::prelude::*;
use chrono::Duration;
use diesel::insert_into;
use diesel::prelude::*;
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome::*;
use rocket::State;

#[derive(Deserialize, Serialize, Debug)]
pub struct Session {
    pub user: String,
    pub scope: Vec<String>,
    pub issued: String,
}

impl<'a, 'r> FromRequest<'a, 'r> for &'a Session {
    type Error = &'a ApiError;

    fn from_request(r: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let session = r.local_cache(|| {
            let db = r.guard::<UserDbConn>().unwrap();
            let session_conf = r.guard::<State<SessionSettings>>().unwrap();
            let session_token = r
                .cookies()
                .get_private("session_token")
                .and_then(|cookie| cookie.value().parse().ok())
                .unwrap_or_default();

            verify_session_token(&db, session_conf.inner(), session_token)
        });

        match session {
            Ok(s) => Success(s),
            Err(_e) => Forward(()),
        }
    }
}

fn fetch_session_token(
    conn: &UserDbConn,
    session: &Session,
    st: String,
) -> Result<SessionToken, ApiError> {
    use crate::schema::session_tokens::dsl::*;
    let db_conn = &conn.0;

    match user::fetch_user(conn, session.user.clone()) {
        Some(user_entry) => {
            match session_tokens
                .filter(session_token.eq(st.clone()))
                .filter(uid.eq(user_entry.get_id()))
                .load::<SessionToken>(db_conn)
            {
                Ok(mut token) => {
                    if token.len() == 1 {
                        let token = token.pop().unwrap();
                        if !token.expired() {
                            Ok(token)
                        } else {
                            println!("Token expired");
                            Err(ApiError::ExpiredToken)
                        }
                    } else {
                        println!("More than one token found. Invalidating them all");
                        expire_session_token(conn, st);
                        Err(ApiError::Internal)
                    }
                }
                Err(e) => {
                    println!("Failed to fetch session: {}", e);
                    Err(ApiError::NoToken)
                }
            }
        }
        None => {
            println!("User '{}' not found", session.user);
            Err(ApiError::NotFound)
        }
    }
}

fn update_session_time(
    conn: &UserDbConn,
    session_conf: &SessionSettings,
    mut st: SessionToken,
) -> SessionToken {
    use crate::schema::session_tokens::dsl::*;
    let db_conn = &conn.0;
    let duration: i64 = session_conf.1;

    // We don't alter the duration when it's set to <= 0 (infinite)
    if duration <= 0 {
        return st;
    }
    let duration = Duration::seconds(duration);

    let dt = Utc::now() + duration;
    let dt = dt.to_rfc3339();
    let target = session_tokens.filter(session_token.eq(st.get_session_token()));

    if let Err(e) = diesel::update(target)
        .set(valid_until.eq(dt.clone()))
        .execute(db_conn)
    {
        println!(
            "Failed to update session time: {}\nReturning original token",
            e
        );
        st
    } else {
        st.valid_until = dt;
        st
    }
}

pub fn expire_session_token(conn: &UserDbConn, session: String) {
    use crate::schema::session_tokens::dsl::*;
    let db_conn = &conn.0;

    let dt = Utc::now().to_rfc3339();
    let target = session_tokens.filter(session_token.eq(session));
    diesel::update(target)
        .set(valid_until.eq(dt))
        .execute(db_conn)
        .unwrap();
}

fn verify_session_token(
    conn: &UserDbConn,
    session_conf: &SessionSettings,
    session_token: String,
) -> Result<Session, ApiError> {
    let token_key = &session_conf.0.as_bytes();
    if let Ok(token_key) = Branca::new(token_key) {
        match token_key.decode(session_token.as_str(), 0) {
            Ok(payload) => {
                let session: Result<Session, serde_json::Error> =
                    serde_json::from_str(payload.as_str());
                match session {
                    Ok(session) => match fetch_session_token(conn, &session, session_token) {
                        Ok(st) => {
                            if st.expired() {
                                println!("Token is expired");
                                return Err(ApiError::ExpiredToken);
                            }
                            let _st = update_session_time(conn, session_conf, st);
                            return Ok(session);
                        }
                        Err(e) => {
                            println!("Failed to retrieve token: {}", e);
                            return Err(ApiError::InvalidToken);
                        }
                    },
                    Err(_e) => {
                        println!("Invalid token!");
                        return Err(ApiError::InvalidToken);
                    }
                }
            }
            Err(_e) => {
                println!("Invalid token!");
                return Err(ApiError::InvalidToken);
            }
        }
    }

    Err(ApiError::Internal)
}

pub fn create_session_token(
    conn: &UserDbConn,
    session_conf: &SessionSettings,
    username: String,
    scope: Vec<String>,
) -> Result<String, ApiError> {
    let now = Utc::now();
    let issued_at = now.to_rfc3339();
    let message = Session {
        user: username.clone(),
        scope,
        issued: issued_at.clone(),
    };
    let message = serde_json::to_string(&message).unwrap();

    match user::fetch_user(conn, username.clone()) {
        Some(user_entry) => {
            let branca_token = &session_conf.0.as_bytes();
            match Branca::new(branca_token) {
                Ok(branca_token) => match branca_token.encode(message.as_str()) {
                    Ok(st) => {
                        use crate::schema::session_tokens::dsl::*;
                        let db_conn = &conn.0;

                        let mut duration: i64 = session_conf.1;
                        if duration < 0 {
                            duration = 0;
                        }
                        let duration = Duration::seconds(duration);
                        let dt = now + duration;
                        let dt = dt.to_rfc3339();

                        if let Ok(_) = insert_into(session_tokens)
                            .values((
                                uid.eq(user_entry.get_id()),
                                session_token.eq(st.clone()),
                                issued.eq(issued_at),
                                valid_until.eq(dt),
                            ))
                            .execute(db_conn)
                        {
                            Ok(st)
                        } else {
                            println!("Failed to insert session token!");
                            Err(ApiError::Internal)
                        }
                    }
                    Err(e) => {
                        println!("Failed to generate session token: {}", e);
                        Err(ApiError::Internal)
                    }
                },
                Err(e) => {
                    println!("Failed to generate token from secret key: {}", e);
                    Err(ApiError::Internal)
                }
            }
        }
        None => {
            println!("User '{}' not found", username);
            Err(ApiError::NotFound)
        }
    }
}
