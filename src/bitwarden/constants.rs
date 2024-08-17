use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

pub const BW_DEFAULT_VAULT_URL: &str = "https://vault.bitwarden.com";
pub const USER_AGENT: &str = "bw-ssh-agent";

pub fn get_bw_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .default_headers(HeaderMap::from_iter([
            (
                HeaderName::from_static("bitwarden-client-name"),
                HeaderValue::from_static("bw-ssh-agent"),
            ),
            (
                HeaderName::from_static("bitwarden-client-version"),
                HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
            ),
        ]))
        .build()
        .unwrap()
}
