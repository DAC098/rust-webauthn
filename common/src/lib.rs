use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct NewRegistration {
    pub username: Box<str>,
    pub key_name: Box<str>,
}

#[derive(Serialize, Deserialize)]
pub struct NewAuthentication {
    pub username: Box<str>,
}