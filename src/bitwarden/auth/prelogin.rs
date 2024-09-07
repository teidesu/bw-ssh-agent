use serde::Deserialize;
use serde_json::json;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::bitwarden::config::ConfigResponseModel;

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
