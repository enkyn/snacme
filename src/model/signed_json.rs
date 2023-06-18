use super::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SignedJsonHeaderKey {
    Jwk {
        alg: &'static str,
        crv: &'static str,
        kty: &'static str,
        #[serde(rename = "use")]
        usage: &'static str,
        x: String,
        y: String,
    },

    Kid(String),
}

#[derive(Debug, Serialize)]
pub(crate) struct SignedJsonHeader<'a> {
    pub alg: &'static str,
    #[serde(flatten)]
    pub key: &'a SignedJsonHeaderKey,
    pub nonce: String,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignedJson {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Serialize)]
pub(crate) struct SignedJsonThumbprint {
    pub crv: &'static str,
    pub kty: &'static str,
    pub x: String,
    pub y: String,
}