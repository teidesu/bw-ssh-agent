use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use tokio::io::AsyncWrite;

#[derive(Debug, Copy, Clone)]
enum MessageRequest {
    RequestIdentities,
    SignRequest,
    AddIdentity,
    RemoveIdentity,
    RemoveAllIdentities,
    AddIdConstrained,
    AddSmartcardKey,
    RemoveSmartcardKey,
    Lock,
    Unlock,
    AddSmartcardKeyConstrained,
    Extension,
    Unknown,
}

impl MessageRequest {
    fn from_u8(value: u8) -> MessageRequest {
        match value {
            11 => MessageRequest::RequestIdentities,
            13 => MessageRequest::SignRequest,
            17 => MessageRequest::AddIdentity,
            18 => MessageRequest::RemoveIdentity,
            19 => MessageRequest::RemoveAllIdentities,
            25 => MessageRequest::AddIdConstrained,
            20 => MessageRequest::AddSmartcardKey,
            21 => MessageRequest::RemoveSmartcardKey,
            22 => MessageRequest::Lock,
            23 => MessageRequest::Unlock,
            26 => MessageRequest::AddSmartcardKeyConstrained,
            27 => MessageRequest::Extension,
            _ => MessageRequest::Unknown,
        }
    }
}

fn read_message(stream: &mut dyn Read) -> color_eyre::Result<Vec<u8>> {
    let len = stream.read_u32::<BigEndian>()?;

    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf)?;

    Ok(buf)
}

fn write_message(w: &mut dyn Write, string: &[u8]) -> color_eyre::Result<()> {
    w.write_u32::<BigEndian>(string.len() as u32)?;
    w.write_all(string)?;
    Ok(())
}

// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-new-registry-ssh-agent-sign
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SignatureFlags: u32 {
        const reserved = 1 << 0;
        const SSH_AGENT_RSA_SHA2_256 = 1 << 1;
        const SSH_AGENT_RSA_SHA2_512 = 1 << 2;
    }
}

#[derive(Debug)]
pub enum Request {
    RequestIdentities,
    SignRequest {
        // Blob of the public key
        // (encoded as per RFC4253 "6.6. Public Key Algorithms").
        pubkey_blob: Vec<u8>,
        // The data to sign.
        data: Vec<u8>,
        // Request flags.
        flags: u32,
    },
    Extension {
        // The name of the extension.
        name: String,
        // The data to be sent to the extension.
        data: Vec<u8>,
    },
    Unknown,
}

impl Request {
    pub fn read(mut buf: &mut dyn Read) -> color_eyre::Result<Self> {
        let msg = buf.read_u8()?;
        match MessageRequest::from_u8(msg) {
            MessageRequest::RequestIdentities => Ok(Request::RequestIdentities),
            MessageRequest::SignRequest => Ok(Request::SignRequest {
                pubkey_blob: read_message(&mut buf)?,
                data: read_message(&mut buf)?,
                flags: buf.read_u32::<BigEndian>()?,
            }),
            MessageRequest::AddIdentity => Ok(Request::Unknown),
            MessageRequest::RemoveIdentity => Ok(Request::Unknown),
            MessageRequest::RemoveAllIdentities => Ok(Request::Unknown),
            MessageRequest::AddIdConstrained => Ok(Request::Unknown),
            MessageRequest::AddSmartcardKey => Ok(Request::Unknown),
            MessageRequest::RemoveSmartcardKey => Ok(Request::Unknown),
            MessageRequest::Lock => Ok(Request::Unknown),
            MessageRequest::Unlock => Ok(Request::Unknown),
            MessageRequest::AddSmartcardKeyConstrained => Ok(Request::Unknown),
            MessageRequest::Extension => Ok(Request::Extension {
                name: String::from_utf8(read_message(&mut buf)?)?,
                data: read_message(&mut buf)?,
            }),
            MessageRequest::Unknown => Ok(Request::Unknown),
        }
    }
}

enum MessageResponse {
    AgentFailure = 5,
    AgentSuccess = 6,
    AgentIdentitiesAnswer = 12,
    AgentSignResponse = 14,
}

#[derive(Debug)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub key_comment: String,
}

#[derive(Debug)]
pub enum Response {
    Success,
    Failure,
    Identities(Vec<Identity>),
    SignResponse {
        algo_name: String,
        signature: Vec<u8>,
    },
}

impl Response {
    pub async fn write(
        &self,
        mut stream: &mut (impl AsyncWrite + Unpin),
    ) -> color_eyre::Result<()> {
        let mut buf = Vec::new();
        match *self {
            Response::Success => buf.write_u8(MessageResponse::AgentSuccess as u8)?,
            Response::Failure => buf.write_u8(MessageResponse::AgentFailure as u8)?,
            Response::Identities(ref identities) => {
                buf.write_u8(MessageResponse::AgentIdentitiesAnswer as u8)?;
                buf.write_u32::<BigEndian>(identities.len() as u32)?;

                for identity in identities {
                    write_message(&mut buf, &identity.key_blob)?;
                    write_message(&mut buf, identity.key_comment.as_bytes())?;
                }
            }
            Response::SignResponse {
                ref algo_name,
                ref signature,
            } => {
                buf.write_u8(MessageResponse::AgentSignResponse as u8)?;

                let mut full_sig = Vec::new();
                write_message(&mut full_sig, algo_name.as_bytes())?;
                write_message(&mut full_sig, signature)?;

                write_message(&mut buf, full_sig.as_slice())?;
            }
        }

        tokio::io::AsyncWriteExt::write_u32(&mut stream, buf.len() as u32).await?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &buf).await?;

        Ok(())
    }
}
