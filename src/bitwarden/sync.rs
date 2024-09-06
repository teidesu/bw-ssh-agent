use color_eyre::eyre::eyre;
use serde::Deserialize;
use serde_repr::Deserialize_repr;

use super::config::ConfigResponseModel;

// structs are intentionally incomplete to simplify usage

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SyncResponseModel {
    #[serde(rename = "ciphers", alias = "Ciphers")]
    pub ciphers: Vec<CipherDetailsResponseModel>,
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
pub struct CipherDetailsResponseModel {
    #[serde(rename = "creationDate", alias = "CreationDate")]
    pub creation_date: String,
    #[serde(rename = "deletedDate", alias = "DeletedDate")]
    pub deleted_date: Option<String>,
    #[serde(rename = "fields", alias = "Fields")]
    #[serde(default)]
    pub fields: Option<Vec<CipherFieldModel>>,
    #[serde(rename = "id", alias = "Id")]
    pub id: String, // uuid in the scheme
    #[serde(rename = "name", alias = "Name")]
    pub name: Option<String>,
    #[serde(rename = "notes", alias = "Notes")]
    pub notes: Option<String>,
    #[serde(rename = "secureNote", alias = "SecureNote")]
    pub secure_note: Option<CipherSecureNoteModel>,
    #[serde(rename = "type", alias = "Type")]
    pub type_field: CipherType,
    #[serde(rename = "key", alias = "Key")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize_repr)]
#[repr(i32)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CipherFieldModel {
    #[serde(rename = "name", alias = "Name")]
    pub name: Option<String>,
    #[serde(rename = "type", alias = "Type")]
    pub type_field: FieldType,
    #[serde(rename = "value", alias = "Value")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CipherSecureNoteModel {
    #[serde(rename = "type", alias = "Type")]
    pub type_field: u8,
}

pub async fn bw_sync(
    client: &reqwest::Client,
    config: &ConfigResponseModel,
    token: &str,
) -> color_eyre::Result<SyncResponseModel> {
    let url = format!("{}/sync?excludeDomains=true", config.environment.api);

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let mut jd = serde_json::Deserializer::from_str(&response);
    let response = serde_path_to_error::deserialize(&mut jd)
        .map_err(|e| eyre!("Unexpected response: {}", e))?;

    Ok(response)
}
