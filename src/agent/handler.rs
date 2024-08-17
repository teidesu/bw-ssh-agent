use super::protocol::{Request, Response};

#[async_trait::async_trait]
pub trait SSHAgentHandler: Send + Sync {
    async fn identities(&self) -> color_eyre::Result<Response>;
    async fn sign_request(
        &self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> color_eyre::Result<Response>;

    async fn handle_request(&self, request: Request) -> color_eyre::Result<Response> {
        match request {
            Request::RequestIdentities => self.identities().await,
            Request::SignRequest {
                ref pubkey_blob,
                ref data,
                ref flags,
            } => {
                self.sign_request(pubkey_blob.clone(), data.clone(), *flags)
                    .await
            }
            Request::Unknown => Ok(Response::Failure),
            Request::Extension { .. } => Ok(Response::Failure),
        }
    }
}
