use color_eyre::eyre::eyre;
use serde::Deserialize;
use serde_repr::Deserialize_repr;

use super::config::BwConfig;

// structs are intentionally incomplete to simplify usage

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BwSyncResponse {
    #[serde(rename = "Ciphers")]
    pub ciphers: Vec<BwCipher>,
}

#[derive(Debug, Clone, PartialEq, Deserialize_repr)]
#[repr(u8)]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BwCipher {
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
    #[serde(rename = "DeletedDate")]
    pub deleted_date: Option<String>,
    #[serde(rename = "Fields")]
    #[serde(default)]
    pub fields: Option<Vec<Field>>,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
    #[serde(rename = "SecureNote")]
    pub secure_note: Option<SecureNote>,
    #[serde(rename = "Type")]
    pub type_field: CipherType,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Field {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type")]
    pub type_field: i64,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    #[serde(rename = "Type")]
    pub type_field: i64,
}

pub async fn bw_sync(
    client: &reqwest::Client,
    config: &BwConfig,
    token: &str,
) -> color_eyre::Result<BwSyncResponse> {
    let url = format!("{}/sync?excludeDomains=true", config.environment.api);

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?
        .text()
        .await?;

    let mut jd = serde_json::Deserializer::from_str(&response);
    let response = serde_path_to_error::deserialize(&mut jd)
        .map_err(|e| eyre!("Unexpected response at {}", e))?;

    Ok(response)
}
