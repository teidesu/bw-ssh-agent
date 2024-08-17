use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwConfig {
    pub environment: BwEnvironment,
    pub server: Option<BwServer>,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwEnvironment {
    pub api: String,
    pub identity: String,
    pub notifications: String,
    pub sso: String,
    pub vault: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwServer {
    pub name: String,
    pub url: String,
    pub version: Option<String>,
}

pub async fn bw_get_config(
    client: &reqwest::Client,
    server_url: &String,
) -> color_eyre::Result<BwConfig> {
    let url = format!("{}/api/config", server_url);
    let response = client.get(url).send().await?.json::<BwConfig>().await?;
    Ok(response)
}
