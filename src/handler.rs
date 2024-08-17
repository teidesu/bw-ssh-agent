use crate::agent::protocol::Identity;
use crate::agent::{handler::SSHAgentHandler, protocol::Response};
use crate::bitwarden::crypto::decrypt_with_master_key;
use crate::database::Database;
use crate::keychain::Keychain;
use signature::Signer;
use ssh_key::PrivateKey;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

pub struct Handler {
    database: Mutex<Database>,
    keychain: Mutex<Keychain>,
}

impl Handler {
    pub fn new(database: Database, keychain: Keychain) -> Self {
        Self {
            database: Mutex::new(database),
            keychain: Mutex::new(keychain),
        }
    }
}

#[async_trait::async_trait]
impl SSHAgentHandler for Handler {
    async fn identities(&self) -> color_eyre::Result<Response> {
        let db_idents = {
            let database = self.database.lock().await;
            database.get_identities()?
        };

        let mut idents = Vec::new();
        for db_ident in db_idents {
            idents.push(Identity {
                key_blob: db_ident.public_key,
                key_comment: db_ident.name.clone(),
            });
        }
        Ok(Response::Identities(idents))
    }

    async fn sign_request(
        &self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        _flags: u32,
    ) -> color_eyre::Result<Response> {
        let (auth, identity) = {
            let database = self.database.lock().await;

            let Some(identity) = database.get_identity_by_public_key(&pubkey)? else {
                return Ok(Response::Failure);
            };

            let Ok(Some(auth)) = database.get_auth() else {
                return Ok(Response::Failure);
            };

            (auth, identity)
        };

        let symmetric_key = self
            .keychain
            .lock()
            .await
            .decrypt_data(auth.symmetric_key.to_vec())
            .await?;

        let private_key = Zeroizing::new(decrypt_with_master_key(
            &symmetric_key,
            &identity.private_key,
        )?);

        let private_key = PrivateKey::from_openssh(private_key)?;

        let signature = private_key.try_sign(data.as_slice())?;
        let sig_bytes = signature.as_bytes();

        Ok(Response::SignResponse {
            algo_name: private_key.algorithm().to_string(),
            signature: sig_bytes.into(),
        })
    }
}
