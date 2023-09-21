use std::ops::Range;

use hyper::{body::to_bytes, Body, Request, StatusCode};

use futures::{AsyncWriteExt, TryFutureExt};
use tlsn_prover::{Prover, ProverConfig};

use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use
{
   ws_stream_tungstenite :: { *                  } ,
   futures                :: { FutureExt, select, future::{ ok, ready }, StreamExt } ,
   log                   :: { *                  } ,
   async_tungstenite     :: { tokio::{ TokioAdapter, connect_async }} ,
   url                    :: { Url } ,
};

const SERVER_DOMAIN: &str = "twitter.com";
const ROUTE: &str = "i/api/1.1/dm/conversation";
const CONVERSATION_ID: &str = "";

const CLIENT_UUID: &str = "";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

const AUTH_TOKEN: &str = "";
const ACCESS_TOKEN: &str = "";
const CSRF_TOKEN: &str = "";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Basic default prover config
    let config = ProverConfig::builder()
        .id("example")
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Connect to the Notary
	let url    = Url::parse( "ws://127.0.0.1:7788" ).unwrap();
	let socket = ok( url ).and_then( connect_async ).await.expect( "ws handshake" );
    // Ref: https://github.com/najamelan/ws_stream_tungstenite/blob/f136412bda74579385d43c91bac8a8030cb527bf/examples/close.rs#L120
	let notary_socket     = WsStream::new( socket.0 );

    // Connect to the Server (twitter.com)
    // let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
    //     .await
    //     .unwrap();
    let url_app    = Url::parse( "ws://127.0.0.1:55688" ).unwrap();
	let socket_app = ok( url_app ).and_then( connect_async ).await.expect( "ws handshake" );
    // Ref: https://github.com/najamelan/ws_stream_tungstenite/blob/f136412bda74579385d43c91bac8a8030cb527bf/examples/close.rs#L120
	let client_socket     = WsStream::new( socket_app.0 );

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    let prover = Prover::new(config)
        .setup(notary_socket)
        .await
        .unwrap();


    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket).await.unwrap();

    // Spawn the Prover task to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the MPC TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::handshake(mpc_tls_connection.compat())
            .await
            .unwrap();


    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!(
            "https://{SERVER_DOMAIN}/{ROUTE}/{CONVERSATION_ID}.json"
        ))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .header("Authorization", format!("Bearer {ACCESS_TOKEN}"))
        .header(
            "Cookie",
            format!("auth_token={AUTH_TOKEN}; ct0={CSRF_TOKEN}"),
        )
        .header("Authority", SERVER_DOMAIN)
        .header("X-Twitter-Auth-Type", "OAuth2Session")
        .header("x-twitter-active-user", "yes")
        .header("X-Client-Uuid", CLIENT_UUID)
        .header("X-Csrf-Token", CSRF_TOKEN)
        .body(Body::empty())
        .unwrap();

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender.send_request(request).await.unwrap();

    println!("Got a response from the server");

    assert!(response.status() == StatusCode::OK);

    // Close the connection to the server
    let mut client_socket = connection_task.await.unwrap().unwrap().io.into_inner();
    client_socket.close().await.unwrap();

    // The Prover task should be done now, so we can grab it.
    let mut prover = prover_task.await.unwrap().unwrap();
    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) = find_ranges(
        prover.sent_transcript().data(),
        &[
            ACCESS_TOKEN.as_bytes(),
            AUTH_TOKEN.as_bytes(),
            CSRF_TOKEN.as_bytes(),
        ],
    );

    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = public_ranges
        .iter()
        .map(|r| builder.commit_sent(r.clone()).unwrap())
        .collect();

    // Commit to all inbound data in one shot, as we don't need to redact anything in it
    let recv_commitment = builder.commit_recv(0..recv_len).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal(commitment_id).unwrap();
    }
    proof_builder.reveal(recv_commitment).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    // Write the proof to a file in the format expected by `simple_verifier.rs`
    let mut file = tokio::fs::File::create("proof.json").await.unwrap();
    file.write_all(
        serde_json::to_string_pretty(&(&session_proof, &substrings_proof, &SERVER_DOMAIN))
            .unwrap()
            .as_bytes(),
    )
    .await
    .unwrap();

    println!("Notarization completed successfully!");
    println!("The proof has been written to proof.json");
}

/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}
