use std::{io::Cursor, sync::Arc};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, BufWriter},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

use super::{handler::SSHAgentHandler, protocol};

pub struct Agent {
    pub listener: UnixListener,
}

async fn handle_connection(
    socket: UnixStream,
    handler: Arc<Mutex<Box<dyn SSHAgentHandler>>>,
) -> color_eyre::Result<()> {
    let (read, write) = socket.into_split();

    let mut read = BufReader::new(read);
    let mut write = BufWriter::new(write);

    loop {
        let size = read.read_u32().await?;
        let mut buf = vec![0; size as usize];
        read.read_exact(&mut buf).await?;

        let mut cursor = Cursor::new(buf);

        let request = protocol::Request::read(&mut cursor)?;

        let response = handler.lock().await.handle_request(request).await?;

        response.write(&mut write).await?;
        write.flush().await?;
    }
}

impl Agent {
    pub fn new(listener: UnixListener) -> Self {
        Self { listener: listener }
    }

    pub async fn run(&self, handler: Box<dyn SSHAgentHandler>) -> color_eyre::Result<()> {
        let arc = Arc::new(Mutex::new(handler));

        loop {
            let (socket, _) = self.listener.accept().await?;

            let handler_arc = arc.clone();

            tokio::spawn(async move {
                handle_connection(socket, handler_arc)
                    .await
                    .unwrap_or_else(|e| {
                        if e.to_string().contains("unexpected end of file") {
                            return;
                        }

                        eprintln!("Error handling connection: {:?}", e);
                    });
            });
        }
    }
}
