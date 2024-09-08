use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use color_eyre::eyre::eyre;
use serde::de::DeserializeOwned;

use super::identity_dto::{
    IdentityTokenRefreshResponse, IdentityTokenSuccessResponse, PasswordTokenRequest,
    RenewTokenRequest,
};

pub struct IdentityClient<'a> {
    client: &'a reqwest::Client,
    base: &'a str,
    email: &'a str,
}

impl<'a> IdentityClient<'a> {
    pub fn new(client: &'a reqwest::Client, base: &'a str, email: &'a str) -> Self {
        Self {
            client,
            base,
            email,
        }
    }

    pub async fn password_login(
        &self,
        email: &str,
        password: &str,
    ) -> color_eyre::Result<IdentityTokenSuccessResponse> {
        let req = PasswordTokenRequest::new(email, password);
        self.identity_connect(req).await
    }

    pub async fn renew_token(
        &self,
        refresh_token: &str,
    ) -> color_eyre::Result<IdentityTokenRefreshResponse> {
        let req = RenewTokenRequest::new(refresh_token);
        self.identity_connect(req).await
    }

    async fn identity_connect<Req: serde::Serialize, Res: DeserializeOwned>(
        &self,
        request: Req,
    ) -> color_eyre::Result<Res> {
        let url = format!("{}/connect/token", self.base);

        let response = self
            .client
            .post(url)
            .form(&request)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("Auth-Email", URL_SAFE_NO_PAD.encode(self.email))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        serde_json::from_str::<Res>(&response).map_err(|_| eyre!("Unexpected response: {response}"))
    }
}
