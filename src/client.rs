use crate::{Result, DEFAULT_ORIGIN, ENDPOINT_VERSION};

use std::{fmt, sync::Arc, time::Duration};

#[cfg(any(feature = "native-tls", feature = "rustls"))]
use reqwest::tls;
use reqwest::{Method, Url};
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use std::path::PathBuf;
use tokio::sync::RwLock;

use serde::{de::DeserializeOwned, Deserialize};

const DEFAULT_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

const RESPONSE_BODY_LIMIT: usize = 1_024_000;

const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub status: String,
    pub message: String,
    pub code: u16,
}

impl fmt::Display for StatusResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.code, self.status, self.message)
    }
}

#[derive(Debug)]
pub(crate) struct PathAndQuery {
    path: String,
    query: Vec<(String, String)>,
}

impl PathAndQuery {
    pub(crate) fn new(path: String) -> Self {
        Self {
            path,
            query: Vec::new(),
        }
    }

    pub(crate) fn add_query_pair<K, V>(&mut self, key: K, value: V)
    where
        K: ToString,
        V: ToString,
    {
        self.query.push((key.to_string(), value.to_string()));
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    base_url: Url,
    http_client: reqwest::Client,
    pub(crate) token: Arc<RwLock<String>>,
}

impl Client {
    pub(crate) const MAX_PAGE_LIMIT: i64 = 100;

    /// Create a default client
    pub fn new(token: &str) -> Result<Self> {
        let builder = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .https_only(true)
            .user_agent(DEFAULT_USER_AGENT);

        #[cfg(any(feature = "native-tls", feature = "rustls"))]
        let builder = builder.min_tls_version(tls::Version::TLS_1_2);

        let base_url = Url::parse(DEFAULT_ORIGIN)?.join(&format!("{}/", ENDPOINT_VERSION))?;

        let token = Arc::new(RwLock::new(token.to_string()));

        Ok(Self {
            base_url,
            token,
            http_client: builder.build()?,
        })
    }

    pub(crate) async fn get_json<T>(&self, path: PathAndQuery) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut url = self.base_url.join(&path.path)?;
        if !path.query.is_empty() {
            url.query_pairs_mut().extend_pairs(path.query).finish();
        }

        let req = self
            .http_client
            .request(Method::GET, url)
            .bearer_auth(&self.token.read().await)
            .build()?;

        tracing_request(&req);

        let res = self.http_client.execute(req).await?;

        tracing_response(&res);

        if !res.status().is_success() {
            let sr = res.json::<StatusResponse>().await?;
            return Err(sr.into());
        }

        let data = res.json::<T>().await?;

        Ok(data)
    }
}

#[derive(Debug, Default, Clone)]
pub struct ClientBuilder {
    token: String,
    origin: Option<String>,
    user_agent: Option<String>,
    timeout: Option<Duration>,
    trust_dns: Option<bool>,
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    tls: ClientTls,
}

impl ClientBuilder {
    /// Set alternative host
    pub fn set_origin(mut self, host: &str) -> Self {
        self.origin = Some(host.to_string());

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

    /// Set request timeout
    ///
    /// Default: 30 seconds
    pub fn set_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);

        self
    }

    /// Set minimum TLS version
    ///
    /// Default: 1.2
    pub fn set_min_tls(mut self, version: tls::Version) -> Self {
        self.tls.min_version = Some(version);

        self
    }

    /// Set path to CA certificate file in PEM format
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    pub fn set_ca<T: Into<PathBuf>>(mut self, root_ca: T) -> Self {
        let ca = root_ca.into();

        self.tls.root_ca = Some(ca);

        self
    }

    /// Enables/Disables the trust-dns async resolver.
    ///
    /// Default: true
    pub fn set_trust_dns(mut self, enable: bool) -> Self {
        self.trust_dns = Some(enable);

        self
    }

    /// Set path to certificate and private key file in PEM format. Used for TLS client authentication
    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    pub fn set_keypair<T: Into<PathBuf>>(mut self, certificate: T, private_key: T) -> Self {
        let cert = certificate.into();
        let key = private_key.into();

        self.tls.certificate = Some(cert);
        self.tls.private_key = Some(key);

        self
    }

    pub async fn build(self) -> Result<Client> {
        let builder = reqwest::ClientBuilder::new();

        #[cfg(any(feature = "native-tls", feature = "rustls"))]
        let builder = if let Some(v) = self.tls.min_version {
            builder.min_tls_version(v)
        } else {
            builder.min_tls_version(tls::Version::TLS_1_2)
        };

        let builder = if let Some(v) = self.timeout {
            builder.timeout(v)
        } else {
            builder
        };

        let builder = if let Some(v) = self.user_agent {
            builder.user_agent(v)
        } else {
            builder
        };

        #[cfg(any(feature = "native-tls", feature = "rustls"))]
        let builder = if self.tls.root_ca.is_some() {
            let cert = self.tls.read_root_ca().await?;
            builder.add_root_certificate(cert)
        } else {
            builder
        };

        #[cfg(feature = "rustls")]
        let builder = if self.tls.certificate.is_some() {
            let identity = self.tls.read_identity().await?;
            builder.identity(identity)
        } else {
            builder
        };

        let builder = if let Some(v) = self.trust_dns {
            builder.trust_dns(v)
        } else {
            builder
        };

        let base_url = if let Some(h) = &self.origin {
            Url::parse(h)?.join(&format!("{}/", ENDPOINT_VERSION))?
        } else {
            Url::parse(DEFAULT_ORIGIN)?.join(&format!("{}/", ENDPOINT_VERSION))?
        };

        let builder = if base_url.scheme() == "https" {
            builder.https_only(true)
        } else {
            builder
        };

        let token = Arc::new(RwLock::new(self.token.to_string()));

        Ok(Client {
            base_url,
            token,
            http_client: builder.build()?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientTlsError {
    #[error("no root certficate specified")]
    NoRootCA,
    #[error("no private key specified")]
    NoPrivateKey,
    #[error("no certficate specified")]
    NoCertificate,
}

#[cfg(any(feature = "native-tls", feature = "rustls"))]
#[derive(Debug, Default, Clone)]
struct ClientTls {
    root_ca: Option<PathBuf>,
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    min_version: Option<tls::Version>,
}

#[cfg(any(feature = "native-tls", feature = "rustls"))]
impl ClientTls {
    async fn read_root_ca(&self) -> Result<tls::Certificate> {
        let cert = if let Some(p) = &self.root_ca {
            let file = tokio::fs::read(p).await?;
            tls::Certificate::from_pem(&file[..])?
        } else {
            return Err(ClientTlsError::NoRootCA.into());
        };

        Ok(cert)
    }

    #[cfg(feature = "rustls")]
    async fn read_identity(&self) -> Result<tls::Identity> {
        let mut cert = if let Some(p) = &self.certificate {
            tokio::fs::read(p).await?
        } else {
            return Err(ClientTlsError::NoCertificate.into());
        };

        let mut key = if let Some(p) = &self.private_key {
            tokio::fs::read(p).await?
        } else {
            return Err(ClientTlsError::NoPrivateKey.into());
        };

        cert.append(&mut key);

        let identity = tls::Identity::from_pem(&cert[..])?;

        Ok(identity)
    }
}

fn tracing_request(req: &reqwest::Request) {
    let span = tracing::debug_span!(
        "request",
        req.method = ?req.method(),
        req.url = ?req.url().as_str(),
        req.version = ?req.version(),
        headers = ?req.headers()
    );

    tracing::debug!(parent: &span, "sending request");
}

fn tracing_response(res: &reqwest::Response) {
    let span = tracing::debug_span!(
        "response",
        req.status = ?res.status(),
        req.url = ?res.url().as_str(),
        req.version = ?res.version(),
        headers = ?res.headers()
    );

    tracing::debug!(parent: &span, "response received");
}
