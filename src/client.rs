use crate::{Error, Result, DEFAULT_HOST, ENDPOINT_VERSION};

use std::fmt;

#[cfg(feature = "rustls")]
use std::{io::BufReader, path::PathBuf, sync::Arc};

use awc::{
    http::{
        header::{ContentType, USER_AGENT},
        Method, PathAndQuery,
    },
    Client as ActixClient, ClientBuilder as ActixClientBuilder, Connector,
};
use chrono::{serde::ts_seconds, DateTime, Utc};
use jsonwebtoken::dangerous_insecure_decode;
use serde::{de::DeserializeOwned, Deserialize};

#[cfg(feature = "openssl")]
use open_ssl::ssl::{SslConnector, SslFiletype, SslMethod};

#[cfg(feature = "rustls")]
use rust_tls::{internal::pemfile, ClientConfig};

const DEFAULT_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

const RESPONSE_BODY_LIMIT: usize = 1_024_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    status: String,
    message: String,
    code: u16,
}

impl fmt::Display for StatusResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.code, self.status, self.message)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct TokenClaims {
    aud: String,
    #[serde(with = "ts_seconds")]
    exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    iat: DateTime<Utc>,
    iss: String,
    sub: String,
    scope: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ClientBuilder {
    token: String,
    host: Option<String>,
    user_agent: Option<String>,
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    ssl: ClientSSL,
}

impl ClientBuilder {
    /// Set alternative host
    pub fn set_host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());

        self
    }

    /// Set custom User-Agent header
    pub fn set_user_agent(mut self, user_agent: &str) -> Self {
        self.user_agent = Some(user_agent.to_string());

        self
    }

    /// Set authentication token
    pub fn set_token(mut self, token: &str) -> Self {
        self.token = token.to_string();

        self
    }

    /// Set path to CA certificate file in PEM format
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    pub fn set_ca<T: Into<PathBuf>>(mut self, root_ca: T) -> Self {
        let ca = root_ca.into();

        self.ssl.root_ca = Some(ca);

        self
    }

    /// Set path to certificate and private key file in PEM format. Used for TLS client authentication
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    pub fn set_keypair<T: Into<PathBuf>>(mut self, certificate: T, private_key: T) -> Self {
        let cert = certificate.into();
        let key = private_key.into();

        self.ssl.certificate = Some(cert);
        self.ssl.private_key = Some(key);

        self
    }

    pub fn build(self) -> Result<Client> {
        let connector = Connector::new();

        #[cfg(all(not(feature = "rustls"), feature = "openssl"))]
        let connector = connector.ssl(self.ssl.openssl_connector()?);

        #[cfg(all(not(feature = "openssl"), feature = "rustls"))]
        let connector = connector.rustls(Arc::new(self.ssl.rustls_connector()?));

        let client = ActixClientBuilder::default()
            .connector(connector.finish())
            .header(
                USER_AGENT,
                self.user_agent
                    .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string()),
            )
            .finish();

        let host = if let Some(h) = &self.host {
            format!("{}{}", h, ENDPOINT_VERSION)
        } else {
            format!("{}{}", DEFAULT_HOST, ENDPOINT_VERSION)
        };

        Ok(Client {
            host,
            token: self.token,
            client,
        })
    }
}

#[cfg(any(feature = "openssl", feature = "rustls"))]
#[derive(Debug, Default)]
struct ClientSSL {
    root_ca: Option<PathBuf>,
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
}

#[cfg(any(feature = "openssl", feature = "rustls"))]
impl ClientSSL {
    #[cfg(all(not(feature = "rustls"), feature = "openssl"))]
    fn openssl_connector(&self) -> Result<SslConnector> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;

        if let Some(f) = &self.certificate {
            builder.set_certificate_file(f, SslFiletype::PEM)?;
        }
        if let Some(f) = &self.private_key {
            builder.set_private_key_file(f, SslFiletype::PEM)?;
        }
        if let Some(f) = &self.root_ca {
            builder.set_ca_file(f)?;
        }

        Ok(builder.build())
    }

    #[cfg(all(not(feature = "openssl"), feature = "rustls"))]
    fn rustls_connector(&self) -> Result<ClientConfig> {
        let mut config = ClientConfig::new();

        if let Some(f) = &self.certificate {
            let mut buf = BufReader::new(fs::File::open(f)?);
            let cert = pemfile::certs(&mut buf).unwrap();

            let key = if let Some(f) = &self.private_key {
                let mut buf = BufReader::new(fs::File::open(f)?);
                pemfile::rsa_private_keys(&mut buf)
                    .unwrap()
                    .first()
                    .unwrap()
                    .to_owned()
            } else {
                return Err(Error::IOError(io::Error::new(
                    io::ErrorKind::Other,
                    "Private key is missing",
                )));
            };

            config.set_single_client_cert(cert, key)?;
        }

        if let Some(f) = &self.root_ca {
            let mut buf = BufReader::new(fs::File::open(f)?);
            config.root_store.add_pem_file(&mut buf).unwrap();
        }

        Ok(config)
    }
}

pub struct Client {
    host: String,
    token: String,
    client: ActixClient,
}

impl Client {
    pub(crate) const MAX_PAGE_LIMIT: i64 = 100;

    /// Create a default client
    pub fn new(token: &str) -> Self {
        let client = ActixClientBuilder::default()
            .header(USER_AGENT, DEFAULT_USER_AGENT)
            .finish();

        let host = format!("{}{}", DEFAULT_HOST, ENDPOINT_VERSION);

        Self {
            host,
            token: token.to_string(),
            client,
        }
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(&self, path: PathAndQuery) -> Result<T> {
        let req = self
            .client
            .request(Method::GET, format!("{}{}", self.host, path))
            .bearer_auth(&self.token)
            .set(ContentType::json());

        let mut res = req.send().await?;

        if !res.status().is_success() {
            let sr: StatusResponse = res.json().await?;
            return Err(Error::APIError(sr));
        }

        let data = res.json().limit(RESPONSE_BODY_LIMIT).await?;

        Ok(data)
    }

    /// Validate set token
    pub fn token_is_valid(&self) -> bool {
        let claims = match dangerous_insecure_decode::<TokenClaims>(&self.token) {
            Ok(d) => d.claims,
            Err(_) => return false,
        };

        let now = Utc::now();

        if now.ge(&claims.exp) {
            return false;
        }

        true
    }

    /// Refresh authentication token
    pub async fn refresh_token(&mut self) -> Result<()> {
        let resp: TokenResponse = self.get_json("token".parse().unwrap()).await?;

        self.token = resp.token;

        Ok(())
    }
}
