use chrono::prelude::*;

#[derive(Queryable, Debug)]
pub struct User {
    id: i32,
    username: String,
    password: String,
}

impl User {
    pub fn get_id(&self) -> i32 {
        self.id
    }
    pub fn get_username(&self) -> String {
        self.username.clone()
    }
    pub fn get_password(&self) -> String {
        self.password.clone()
    }
}

#[derive(Queryable, Deserialize, Serialize, Debug)]
pub struct SessionToken {
    id: i32,
    uid: i32,
    session_token: String,
    issued: String,
    pub valid_until: String,
}

impl SessionToken {
    pub fn get_id(&self) -> i32 {
        self.id
    }
    pub fn get_uid(&self) -> i32 {
        self.uid
    }
    pub fn get_session_token(&self) -> String {
        self.session_token.clone()
    }
    pub fn get_issued_timestamp(&self) -> String {
        self.issued.clone()
    }
    pub fn expired(&self) -> bool {
        if let Ok(valid_until) = chrono::DateTime::parse_from_rfc3339(&self.valid_until) {
            if let Ok(issued_at) = chrono::DateTime::parse_from_rfc3339(&self.issued) {
                // If the duration is set to 0, there is no expiry
                if valid_until <= issued_at {
                    return false;
                }
                return Utc::now() >= valid_until;
            }
        }

        println!("Failed to parse datetime from database. Expiring token");
        true
    }
}
