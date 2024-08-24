use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponseModel {
    pub environment: EnvironmentConfigResponseModel,
    pub server: Option<ServerConfigResponseModel>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentConfigResponseModel {
    pub api: String,
    pub identity: String,
    pub notifications: String,
    pub sso: String,
    pub vault: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfigResponseModel {
    pub name: String,
    pub url: String,
}

pub async fn bw_get_config(
    client: &reqwest::Client,
    server_url: &String,
) -> color_eyre::Result<ConfigResponseModel> {
    let url = format!("{}/api/config", server_url);
    let response = client.get(url).send().await?.json::<ConfigResponseModel>().await?;
    Ok(response)
}
