/// This is a simple implementation of the notary server with minimal functionalities (without TLS, does not support WebSocket and configuration etc.)
/// For a more functional notary server implementation, please use https://github.com/tlsnotary/notary-server
use std::env;
use std::time::Instant;

use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn_notary::{bind_notary, NotaryConfig};

use futures_util::{AsyncReadExt, AsyncWriteExt};
use
{
   ws_stream_tungstenite :: { *                  } ,
   futures               :: { StreamExt          } ,
   log                   :: { *                  } ,
   tokio                 :: { net::{ TcpStream }           } ,
   async_tungstenite     :: { accept_async, tokio::{ TokioAdapter }} ,
   asynchronous_codec    :: { LinesCodec, Framed } ,
 };

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Allow passing an address to listen on as the first argument of this
    // program, but otherwise we'll just set up our TCP listener on
    // 127.0.0.1:8080 for connections.
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7788".to_string());

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop.
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on: {}", addr);

    // Generate a signing key
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, socket_addr) = listener.accept().await.unwrap();

        println!("Accepted connection from: {}", socket_addr);

        let start = Instant::now();

        let s   = accept_async( TokioAdapter::new(socket) ).await.expect( "ws handshake" );
        let mut ws = WsStream::new( s );

        {
            let signing_key = signing_key.clone();

            // Spawn notarization task to be run concurrently
            tokio::spawn(async move {
                // Setup default notary config. Normally a different ID would be generated
                // for each notarization.
                let config = NotaryConfig::builder().id("example").build().unwrap();

                // Bind the notary to the socket
                let (notary, notary_fut) = bind_notary(config, ws).unwrap();

                // Run the notary
                tokio::try_join!(
                    notary_fut,
                    notary.notarize::<p256::ecdsa::Signature>(&signing_key)
                )
                .unwrap();

                let duration = start.elapsed();

                println!("!@# request costs: {} seconds", duration.as_secs());
            });
        }
    }
}
