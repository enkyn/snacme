use super::*;
use super::signed_json::*;
use super::order::*;

use std::cell::Cell;
use rand::rngs::OsRng;
use p256::ecdsa::{Signature, SigningKey};
use p256::ecdsa::signature::Signer;

#[derive(Deserialize)]
pub(crate) struct AccountData {
    status: String,
    contact: Option<Vec<String>>,
    orders: Option<String>,
}

/// Contains information necessary for signing POST-as-GET requests.
pub(crate) struct Crypto {
    signing_key: SigningKey,
    header_key: SignedJsonHeaderKey,
    pub(crate) thumbprint: String,
}

impl TryFrom<&[u8]> for Crypto {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(SigningKey::from_bytes(bytes.into())
            .map_err(|e| Error::SigningKeyFromBytes(e.to_string()))?)
    }
}

impl TryFrom<SigningKey> for Crypto {
    type Error = Error;

    fn try_from(signing_key: SigningKey) -> Result<Self, Self::Error> {
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let encoded_x = Base64UrlUnpadded::encode_string(point.x().unwrap());
        let encoded_y = Base64UrlUnpadded::encode_string(point.y().unwrap());
        let header_key = SignedJsonHeaderKey::Jwk {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            usage: "sig",
            x: encoded_x.clone(),
            y: encoded_y.clone(),
        };

        let thumbprint_data = SignedJsonThumbprint {
            crv: "P-256",
            kty: "EC",
            x: encoded_x,
            y: encoded_y,
        };
        
        let thumbprint_hash = Sha256::digest(to_json_vec(&thumbprint_data)?);
        let thumbprint = Base64UrlUnpadded::encode_string(&thumbprint_hash);

        Ok(Self { signing_key, header_key, thumbprint })
    }
}

impl Crypto {
    /// Generate a new key ring, signing key, etc.
    fn generate() -> Result<Self, Error> {
        Crypto::try_from(SigningKey::random(&mut OsRng::default()))
    }

    /// Used to update a JWT header key value.
    fn set_header_key(&mut self, key: SignedJsonHeaderKey) {
        self.header_key = key;
    }

    /// Sign the given [Payload].
    fn sign(&self, url: &str, nonce: &str, payload: Payload) -> Result<SignedJson, Error> {
        let header = SignedJsonHeader {
            alg: "ES256",
            key: &self.header_key,
            nonce: nonce.to_string(),
            url: url.to_string(),
        };

        let encoded_header = Base64UrlUnpadded::encode_string(&to_json_vec(&header)?);
        let payload = match payload {
            Payload::Empty => String::new(),
            Payload::EmptyObject {} => Base64UrlUnpadded::encode_string(&to_json_vec(&payload)?),
            _ => Base64UrlUnpadded::encode_string(&to_json_vec(&payload)?)
        };
        let signature: Signature = self.signing_key
            .sign(format!("{}.{}", encoded_header, payload).as_bytes());

        Ok(SignedJson {
            protected: encoded_header,
            payload: payload,
            signature: Base64UrlUnpadded::encode_string(signature.to_vec().as_ref()),
        })
    }
}

/// Necessary data for keeping track of account state.
pub struct Account {
    directory: Directory,
    pub(crate) crypto: Crypto,
    nonce: Cell<Option<String>>,

    data: AccountData,
    order_urls: Vec<String>,
}

impl TryFrom<&[u8]> for Account {
    type Error = Error;

    // Apologies for the ugly parsing. At least it works though.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut index = 0;
        let mut crypto: Option<Crypto> = None;
        let mut directory: Option<Directory> = None;
        let mut order_urls: Option<Vec<String>> = None;
        while index < bytes.len() {
            index += match bytes[index] {
                // `Crypto`
                0 => {
                    index += 1;

                    let len_bytes: [u8; USIZE_LEN] = bytes[index..index+USIZE_LEN].try_into()
                        .map_err(|_| Error::ParseFromBytes("Crypto bytes length".to_string()))?;
                    
                    let crypto_len = usize::from_be_bytes(len_bytes);
                    index += USIZE_LEN;

                    let crypto_bytes = &bytes[index..index + crypto_len];
                    crypto = Some(Crypto::try_from(crypto_bytes)?);
                    
                    crypto_len
                },
                
                // `Directory`
                1 => {
                    index += 1;

                    let len_bytes: [u8; USIZE_LEN] = bytes[index..index+USIZE_LEN].try_into()
                        .map_err(|_| Error::ParseFromBytes("Directory bytes length".to_string()))?;
                    
                    let directory_len = usize::from_be_bytes(len_bytes);
                    index += USIZE_LEN;

                    let directory_bytes = &bytes[index..index + directory_len];
                    directory = Some(from_json_bytes(directory_bytes)?);
                    
                    directory_len
                }

                // Order URLs
                2 => {
                    index += 1;

                    let len_bytes: [u8; USIZE_LEN] = bytes[index..index+USIZE_LEN].try_into()
                        .map_err(|_| Error::ParseFromBytes("order_urls bytes length".to_string()))?;
                    
                    let urls_len = usize::from_be_bytes(len_bytes);
                    index += USIZE_LEN;

                    let urls_bytes = &bytes[index..index+urls_len];
                    order_urls = Some(from_json_bytes(urls_bytes)?);
                    
                    urls_len
                },

                // Unknown
                _ => return Err(Error::ParseFromBytes("unknown bytes".to_string())),
            };
        }
        
        // TODO: Perhaps match here and generate/request if `None`?
        let mut crypto = crypto.unwrap();
        let directory = directory.unwrap();

        if let Some(ref kid) = directory.account {
            crypto.set_header_key(SignedJsonHeaderKey::Kid(kid.clone()));
        }

        let response = http_head(&directory.new_nonce)?;
        let nonce = response.header("replay-nonce")
            .expect("failed to retrieve nonce");

        let account_url = directory.account.as_ref().unwrap();
        let signed_json = crypto.sign(account_url, nonce, Payload::Empty)?;
        let response = http_post(account_url, signed_json)?;
        let new_nonce = response.header("replay-nonce")
            .map(|s| s.to_string());

        Ok(Self {
            directory: directory,
            crypto: crypto,
            nonce: Cell::new(new_nonce),
            data: response.into_json()
                .map_err(|e| Error::ResponseIntoJson(e.to_string()))?,
            order_urls: order_urls.unwrap_or(Vec::new()),
        })

    }
}

impl Account {
    /// Generate a new account for the chosen Certificate Authority.
    pub fn generate(ca: CertificateAuthority) -> Result<Self, Error> {
        let mut directory: Directory = get_as_json(ca.into())?;
        let mut crypto = Crypto::generate()?;
        let nonce_response = http_head(&directory.new_nonce)?;
        let nonce = nonce_response.header("replay-nonce")
            .expect("failed to retrieve nonce");
        
        let payload = Payload::NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
        };

        let signed_json = crypto.sign(&directory.new_account, nonce, payload)?;
        let response = http_post(&directory.new_account, signed_json)?;

        // Extract the new nonce.
        let new_nonce = response.header("replay-nonce")
            .map(|s| s.to_string());
        
        // Store the account URL.
        directory.account = response.header("location")
            .map(|s| s.to_string());
        
        // If the account URL exists, change `crypto`'s `header_key` value.
        if let Some(ref kid) = directory.account {
            crypto.set_header_key(SignedJsonHeaderKey::Kid(kid.clone()));
        }

        Ok(Self {
            directory: directory,
            crypto: crypto,
            nonce: Cell::new(new_nonce),
            data: response.into_json()
                .map_err(|e| Error::ResponseIntoJson(e.to_string()))?,
            order_urls: Vec::new(),
        })
    }

    /// Gets the last stored nonce, or asks the server for a new one.
    fn get_nonce(&self) -> Result<String, Error> {
        if let Some(nonce) = self.nonce.take() {
            Ok(nonce)
        } else {
            let nonce = http_head(&self.directory.new_nonce)?
                .header("replay-nonce")
                .expect("failed to retrieve nonce")
                .to_string();
            
            self.nonce.set(Some(nonce.clone()));

            Ok(nonce)
        }
    }

    /// Extracts the nonce from the given `response` and stores it.
    fn set_nonce(&self, response: &Response) {
        let nonce = response.header("replay-nonce")
            .map(|s| s.to_string());
        
        self.nonce.set(nonce);
    }

    /// Signs the [Payload], sends an HTTP POST, then updates the stored nonce.
    pub(crate) fn post(&self, url: &str, payload: Payload) -> Result<Response, Error> {
        let nonce = self.get_nonce()?;
        let signed_json = self.crypto.sign(url, &nonce, payload)?;
        let response = http_post(url, signed_json)?;

        self.set_nonce(&response);

        Ok(response)
    }

    /// Same as `Account::post`, but additionally converts the response to a struct.
    pub(crate) fn post_as_json<T: for <'a> Deserialize<'a>>(&self, url: &str, payload: Payload) -> Result<T, Error> {
        let response = self.post(url, payload)?;

        response.into_json()
            .map_err(|e| Error::ResponseIntoJson(e.to_string()))
    }

    /// Request a new [Order] to be created for the given domains/identifiers.
    /// ([RFC 8555§7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4))
    pub fn create_order(&mut self, domains: &[&str]) -> Result<Order, Error> {
        let identifiers: Vec<Identifier> = domains.iter()
            .map(|d| Identifier {
                r#type: "dns".to_string(),
                value: d.to_string(),
            })
            .collect();
        
        let payload = Payload::NewOrder {
            identifiers: &identifiers,
        };

        let response = self.post(&self.directory.new_order, payload)?;
        let order_url = match response.header("location") {
            Some(url) => url.to_string(),
            None => return Err(Error::ResponseLacksLocation(response)),
        };
        let order_data: OrderData = response.into_json()
            .map_err(|e| Error::ResponseIntoJson(e.to_string()))?;

        self.order_urls.push(order_url.clone());

        Ok(Order {
            url: order_url,
            data: order_data,
            account: self,
            certificate: None,
        })
    }

    /// Serialize necessary [Account] data as bytes.
    pub fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();

        // Mark the next portion of bytes as being the `Crypto`.
        bytes.push(0);

        // Serialize the necessary `Crypto` information.
        let crypto_bytes = self.crypto.signing_key.to_bytes();
        bytes.extend_from_slice(&crypto_bytes.len().to_be_bytes());
        bytes.extend_from_slice(&crypto_bytes);

        // `Directory`
        bytes.push(1);

        let directory_bytes = to_json_vec(&self.directory)?;
        bytes.extend_from_slice(&directory_bytes.len().to_be_bytes());
        bytes.extend_from_slice(&directory_bytes);

        // Order URLs
        bytes.push(2);

        let urls_bytes = to_json_vec(&self.order_urls)?;
        bytes.extend_from_slice(&urls_bytes.len().to_be_bytes());
        bytes.extend_from_slice(&urls_bytes);

        Ok(bytes)
    }
}