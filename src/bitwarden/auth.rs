use color_eyre::eyre::eyre;
use serde::Deserialize;
use serde_json::json;
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::config::ConfigResponseModel;

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Clone, Debug)]
#[repr(u8)]
pub enum KdfType {
    Pbkdf2Sha256 = 0,
    Argon2id = 1,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PreloginResponseModel {
    #[serde(rename = "kdf", alias = "Kdf")]
    pub kdf: KdfType,
    #[serde(rename = "kdfIterations", alias = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "kdfMemory", alias = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(rename = "kdfParallelism", alias = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct BwAuthResponse {
    #[serde(rename = "Kdf")]
    pub kdf: u32,
    #[serde(rename = "KdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "KdfMemory")]
    pub kdf_memory: Option<i64>,
    #[serde(rename = "KdfParallelism")]
    pub kdf_parallelism: Option<i64>,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "ResetMasterPassword")]
    pub reset_master_password: bool,
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "refresh_token")]
    pub refresh_token: String,
    #[serde(rename = "expires_in")]
    pub expires_in: i64,
    pub scope: String,
    #[serde(rename = "token_type")]
    pub token_type: String,
}

pub async fn bw_prelogin(
    client: &reqwest::Client,
    config: &ConfigResponseModel,
    email: &str,
) -> color_eyre::Result<PreloginResponseModel> {
    let url = format!("{}/accounts/prelogin", config.environment.identity);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );

    let body = json!({
        "email": email,
    });

    let resp = client
        .post(url)
        .headers(headers)
        .body(body.to_string())
        .send()
        .await?
        .json::<PreloginResponseModel>()
        .await?;

    Ok(resp)
}

pub async fn bw_login(
    client: &reqwest::Client,
    config: &ConfigResponseModel,
    email: &str,
    password: &str,
) -> color_eyre::Result<BwAuthResponse> {
    let url = format!("{}/connect/token", config.environment.identity);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let body = serde_urlencoded::to_string([
        ("grant_type", "password"),
        ("username", email),
        ("password", password),
        ("scope", "api offline_access"),
        ("client_id", "browser"),
        ("deviceType", "21"), // SDK
        ("deviceName", "bw-ssh-agent"),
        (
            "deviceIdentifier",
            uuid::Uuid::new_v4().to_string().as_str(),
        ),
        ("devicePushToken", ""),
    ])?;

    let response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await?
        .text()
        .await?;

    let response = serde_json::from_str::<BwAuthResponse>(&response)
        .map_err(|_| eyre!("Unexpected response: {}", response))?;

    Ok(response)
}
