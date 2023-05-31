use std::println;

use hyper::{body::to_bytes, Body, Request, StatusCode};
use tlsn_notary::{Notary, NotaryConfig};
use tlsn_prover::{Prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[tokio::test]
async fn test() {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), notary(socket_1));
}

async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let dns = "tlsnotary.org";
    let server_socket = tokio::net::TcpStream::connect(dns.to_string() + ":443")
        .await
        .unwrap();
    let server_socket = server_socket.compat();

    let (prover, server_socket) = Prover::new(
        ProverConfig::builder().id("test").build().unwrap(),
        dns,
        server_socket,
        notary_socket.compat(),
    )
    .unwrap();

    tokio::spawn(async move {
        if let Err(e) = prover.run().await {
            println!("Error in prover: {}", e);
        }
    });

    println!("starting handshake");

    let (mut request_sender, connection) = hyper::client::conn::handshake(server_socket.compat())
        .await
        .unwrap();

    println!("handshake done");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("Error in connection: {}", e);
        }
    });

    let request = Request::builder()
        .header("Host", "tlsnotary.org")
        .method("GET")
        .body(Body::from(""))
        .unwrap();

    println!("sending request");

    let response = request_sender.send_request(request).await.unwrap();

    println!("request sent");

    assert!(response.status() == StatusCode::OK);

    println!(
        "Response: {:?}",
        to_bytes(response.into_body()).await.unwrap()
    );
}

async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let mut notary = Notary::new(NotaryConfig::builder().id("test").build().unwrap());

    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    notary
        .run::<_, p256::ecdsa::Signature>(socket.compat(), &signing_key)
        .await
        .unwrap();
}
