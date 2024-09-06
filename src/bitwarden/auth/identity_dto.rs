use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct PasswordTokenRequest {
    #[serde(rename = "grant_type")]
    grant_type: &'static str,
    #[serde(rename = "client_id")]
    client_id: &'static str,
    #[serde(rename = "deviceType")]
    device_type: u8,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: &'static str,
    #[serde(rename = "username")]
    username: String,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "scope")]
    scope: &'static str,
}

impl PasswordTokenRequest {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            grant_type: "password",
            client_id: "browser",
            device_type: 21,
            device_identifier: uuid::Uuid::new_v4().to_string(),
            device_name: "bw-ssh-agent",
            username: username.to_string(),
            password: password.to_string(),
            scope: "api offline_access",
        }
    }
}

#[derive(Serialize, Debug)]
pub struct RenewTokenRequest {
    #[serde(rename = "grant_type")]
    grant_type: &'static str,
    #[serde(rename = "client_id")]
    client_id: &'static str,
    #[serde(rename = "refresh_token")]
    refresh_token: String,
}

impl RenewTokenRequest {
    pub fn new(refresh_token: &str) -> Self {
        Self {
            grant_type: "refresh_token",
            client_id: "browser",
            refresh_token: refresh_token.to_string(),
        }
    }
}

#[derive(Serialize, Debug)]
pub enum TokenConnectRequest {
    Password(PasswordTokenRequest),
    Renew(RenewTokenRequest),
}

#[derive(Default, Debug, Clone, PartialEq, Deserialize)]
pub struct IdentityTokenSuccessResponse {
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
    pub expires_in: u64,
    pub scope: String,
    #[serde(rename = "token_type")]
    pub token_type: String,
}

#[derive(Deserialize, Debug)]
pub struct IdentityTokenRefreshResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
}
