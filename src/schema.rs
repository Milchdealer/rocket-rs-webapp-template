table! {
    session_tokens (id) {
        id -> Integer,
        uid -> Integer,
        session_token -> Text,
        issued -> Text,
        valid_until -> Text,
    }
}

table! {
    users (id) {
        id -> Integer,
        username -> Text,
        password -> Text,
    }
}

joinable!(session_tokens -> users (uid));

allow_tables_to_appear_in_same_query!(session_tokens, users,);
