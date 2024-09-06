use color_eyre::eyre::eyre;

use super::identity_dto::{
    IdentityTokenRefreshResponse, IdentityTokenSuccessResponse, PasswordTokenRequest,
    RenewTokenRequest,
};

pub struct IdentityClient<'a> {
    client: &'a reqwest::Client,
    base: &'a str,
}

impl<'a> IdentityClient<'a> {
    pub fn new(client: &'a reqwest::Client, base: &'a str) -> Self {
        Self { client, base }
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

    async fn identity_connect<Req: serde::Serialize, Res: for<'de> serde::Deserialize<'de>>(
        &self,
        request: Req,
    ) -> color_eyre::Result<Res> {
        let url = format!("{}/connect/token", self.base);

        let body = serde_urlencoded::to_string(request)?;

        let response = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        serde_json::from_str::<Res>(&response).map_or_else(
            |_| Err(eyre!("Unexpected response: {}", response)),
            |r| Ok(r),
        )
    }
}
