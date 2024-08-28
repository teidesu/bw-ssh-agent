use crate::agent::protocol::{Identity, SignatureFlags};
use crate::agent::{handler::SSHAgentHandler, protocol::Response};
use crate::bitwarden::crypto::bw_decrypt_encstr;
use crate::database::Database;
use crate::keychain::Keychain;
use color_eyre::eyre::eyre;
use sha2::{Sha256, Sha512};
use signature::SignatureEncoding;
use signature::Signer;
use ssh_key::private::KeypairData;
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
        flags: u32,
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

        let mut symmetric_key = self
            .keychain
            .lock()
            .await
            .decrypt_data(auth.symmetric_key.to_vec())
            .await?;

        if let Some(intermediate_key) = &identity.intermediate_key {
            symmetric_key = Zeroizing::new(bw_decrypt_encstr(&symmetric_key, intermediate_key)?);
        }

        let private_key = Zeroizing::new(bw_decrypt_encstr(&symmetric_key, &identity.private_key)?);

        let private_key = PrivateKey::from_openssh(private_key)?;

        let (signature, algo_name) = match private_key.key_data() {
            KeypairData::Rsa(keypair) => {
                let flags = SignatureFlags::from_bits_truncate(flags);

                let res = if flags.intersects(SignatureFlags::SSH_AGENT_RSA_SHA2_256) {
                    (
                        rsa::pkcs1v15::SigningKey::<Sha256>::try_from(keypair)?
                            .try_sign(&data)?
                            .to_vec(),
                        String::from("rsa-sha2-256"),
                    )
                } else if flags.intersects(SignatureFlags::SSH_AGENT_RSA_SHA2_512) {
                    (
                        rsa::pkcs1v15::SigningKey::<Sha512>::try_from(keypair)?
                            .try_sign(&data)?
                            .to_vec(),
                        String::from("rsa-sha2-512"),
                    )
                } else {
                    Err(eyre!("Server requested RSA SHA-1, but it's not supported"))?
                };

                res
            }
            // other algorithms do not depend on the server request
            _ => {
                let res = private_key.try_sign(data.as_slice())?;
                (res.to_bytes(), res.algorithm().to_string())
            }
        };

        Ok(Response::SignResponse {
            algo_name,
            signature,
        })
    }
}
