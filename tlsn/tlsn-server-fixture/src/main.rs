use std::env;

use tlsn_server_fixture::bind;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{info, Level};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let listener = TcpListener::bind(&format!("0.0.0.0:{port}")).await.unwrap();

    info!("Server is running on port {}", port);

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                info!("New connection from {}", addr);
                tokio::spawn(bind(socket.compat_write()));
            }
            Err(e) => {
                info!("Failed to accept connection: {}", e);
            }
        }
    }
}
