use super::*;

pub enum AuthStatus {
    Invalid,
    Pending,
    Valid,
}

impl From<&str> for AuthStatus {
    fn from(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "valid" => Self::Valid,
            _ => Self::Invalid,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthData {
    pub status: String,
    expires: Option<String>,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
    wildcard: Option<bool>,
}

#[derive(Debug)]
pub struct Authorization<'a> {
    pub(crate) url: &'a str,
    pub(crate) data: AuthData,
    pub challenge: Challenge,
}

impl<'a> Authorization<'a> {
    pub fn status(&self) -> AuthStatus {
        AuthStatus::from(self.data.status.as_str())
    }
}