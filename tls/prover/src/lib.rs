use config::ProverConfig;
use std::{future::Future, net::TcpStream};
use tls_client::ClientConnection;

use self::buffer::ExchangeBuffer;

mod buffer;
mod config;

pub struct Prover {
    tls_connection: ClientConnection,
    tcp_stream: TcpStream,
    buffer: ExchangeBuffer,
}

impl Prover {
    pub fn new(_config: ProverConfig) -> Self {
        todo!();
    }

    // Caller needs to run future on executor
    pub fn run(&mut self) -> impl Future<Output = Result<(), ProverError>> + '_ {
        async { Ok(()) }
        //        async move {
        //            loop {
        //                // Pull requests from the request buffer
        //                self.tls_connection.read_tls(&mut self.tcp_stream)?;
        //                self.tls_connection.process_new_packets().await?;
        //                self.tls_connection.reader().read_to_end(&mut self.buffer)?;
        //
        //                // Push responses into the response buffer
        //                self.tls_connection
        //                    .write_all_plaintext(&self.buffer)
        //                    .await?;
        //                self.tls_connection.write_tls(&mut self.tcp_stream)?;
        //            }
        //        }
        //    }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("TLS client error: {0}")]
    TlsClientError(#[from] tls_client::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}
