use color_eyre::eyre::eyre;

use crate::{database::Database, utils::get_current_unix_timestamp};

use super::identity::IdentityClient;

pub struct TokenManager<'a> {
    db: &'a Database,
    identity: &'a IdentityClient<'a>,
    access_token: String,
    refresh_token: &'a str,
    expires_at: u64,
}

impl<'a> TokenManager<'a> {
    // official implementation uses 5 * 60, but I think 60 seconds should be enough
    const TOKEN_RENEW_MARGIN_SECONDS: u64 = 60;

    pub fn new(
        db: &'a Database,
        identity: &'a IdentityClient<'a>,
        // an initial data known from auth to avoid fetching from the db twice
        access_token: String,
        refresh_token: &'a str,
        expires_at: u64,
    ) -> Self {
        Self {
            db,
            identity,
            access_token,
            refresh_token,
            expires_at,
        }
    }

    pub async fn get_access_token(&mut self) -> color_eyre::Result<&str> {
        if get_current_unix_timestamp() > self.expires_at - Self::TOKEN_RENEW_MARGIN_SECONDS {
            let res = self.identity.renew_token(self.refresh_token).await
                .map_err(|e| eyre!("Error renewing the access token. Try logging in using \"bw-ssh-agent login\"{e}"))?;

            self.access_token = res.access_token;
            self.expires_at = get_current_unix_timestamp() + res.expires_in;

            self.db.update_auth(&self.access_token, self.expires_at)?;

            println!("Renewed access token");
        }

        Ok(self.access_token.as_str())
    }
}
