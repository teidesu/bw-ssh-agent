use crate::{
    database::{AuthDto, Database},
    utils::get_current_unix_timestamp,
};

use super::identity::IdentityClient;

pub struct TokenManager<'a> {
    db: &'a Database,
    identity: &'a IdentityClient<'a>,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
}

impl<'a> TokenManager<'a> {
    // official implementation uses 5 * 60, but I think 60 seconds should be enough
    const TOKEN_RENEW_MARGIN_SECONDS: u64 = 60;

    pub fn new(
        db: &'a Database,
        identity: &'a IdentityClient<'a>,
        auth: &'a AuthDto, // an initial auth to avoid fetching from the db twice
    ) -> Self {
        Self {
            db,
            identity,
            access_token: auth.access_token.to_string(),
            refresh_token: auth.refresh_token.to_string(),
            expires_at: auth.expires_at,
        }
    }

    pub async fn get_access_token(&mut self) -> color_eyre::Result<&str> {
        if get_current_unix_timestamp() > self.expires_at - Self::TOKEN_RENEW_MARGIN_SECONDS {
            let res = self.identity.renew_token(&self.refresh_token).await?;

            self.access_token = res.access_token;
            self.expires_at = get_current_unix_timestamp() + res.expires_in;

            self.db.update_auth(&self.access_token, self.expires_at)?;

            println!("Renewed access token");
        }

        Ok(self.access_token.as_str())
    }
}
