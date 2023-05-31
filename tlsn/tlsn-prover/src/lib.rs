use bytes::Bytes;
use futures::{
    channel::{self, oneshot::Canceled},
    future::{join, try_join, FusedFuture},
    select_biased, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt, SinkExt,
    StreamExt,
};
use rand::Rng;
use std::{io::Read, pin::Pin, sync::Arc};
use tlsn_tls_mpc::{setup_components, MpcTlsLeader, TlsRole};

use actor_ot::{create_ot_receiver, create_ot_sender, ReceiverActorControl, SenderActorControl};
use mpc_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpc_share_conversion as ff;
use tls_client::{client::InvalidDnsNameError, Backend, ClientConnection, ServerName};
use tlsn_core::transcript::Transcript;
use uid_mux::{yamux, UidYamux, UidYamuxControl};
use utils_aio::{
    codec::BincodeMux,
    mux::{MuxChannel, MuxerError},
};

mod config;
mod state;
mod tls_conn;

pub use config::ProverConfig;
pub use tls_conn::TLSConnection;

pub use state::{Initialized, Notarizing, ProverState};

const RX_TLS_BUF_SIZE: usize = 2 << 13; // 8 KiB
const RX_BUF_SIZE: usize = 2 << 13; // 8 KiB

#[derive(Debug)]
pub struct Prover<T: ProverState> {
    config: ProverConfig,
    state: T,
}

impl<S, T> Prover<Initialized<S, T>>
where
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    pub fn new(
        config: ProverConfig,
        dns: &str,
        server_socket: S,
        notary_socket: T,
    ) -> Result<(Self, TLSConnection), ProverError> {
        let (tx_sender, tx_receiver) = channel::mpsc::channel::<Bytes>(10);
        let (rx_sender, rx_receiver) = channel::mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_tls_sender, close_tls_receiver) = channel::oneshot::channel::<()>();

        let tls_conn = TLSConnection::new(tx_sender, rx_receiver, close_tls_sender);

        let muxer = UidYamux::new(yamux::Config::default(), notary_socket, yamux::Mode::Client);
        let mux = BincodeMux::new(muxer.control());

        let server_name = ServerName::try_from(dns)?;

        Ok((
            Self {
                config,
                state: Initialized {
                    server_name,
                    server_socket,
                    muxer,
                    mux,
                    tx_receiver,
                    rx_sender,
                    close_tls_receiver,
                    transcript_tx: Transcript::new("tx", vec![]),
                    transcript_rx: Transcript::new("rx", vec![]),
                },
            },
            tls_conn,
        ))
    }

    pub async fn run(self) -> Result<Prover<Notarizing>, ProverError> {
        let Initialized {
            server_name,
            server_socket,
            muxer,
            mux,
            tx_receiver,
            rx_sender,
            close_tls_receiver,
            mut transcript_tx,
            mut transcript_rx,
        } = self.state;

        let mut muxer_fut = Box::pin(
            async move {
                let mut muxer = muxer;
                muxer.run().await
            }
            .fuse(),
        );

        let (mpc_tls, vm, ot_recv, gf2, mut ot_fut) = futures::select! {
            res = &mut muxer_fut => panic!(),
            res = setup_mpc_backend(&self.config, mux).fuse() => res?,
        };

        let mut root_store = tls_client::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client =
            ClientConnection::new(Arc::new(config), Box::new(mpc_tls), server_name).unwrap();

        futures::select! {
            res = &mut muxer_fut => panic!(),
            res = &mut ot_fut => panic!(),
            res = run_client(
                client,
                server_socket,
                &mut transcript_tx,
                &mut transcript_rx,
                tx_receiver,
                rx_sender,
                close_tls_receiver,
            ).fuse() => res?,
        }

        Ok(Prover {
            config: self.config,
            state: Notarizing {
                transcript_tx,
                transcript_rx,
            },
        })
    }
}

impl Prover<Notarizing> {
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    pub fn send_commitments(&mut self) -> Result<(), ProverError> {
        todo!()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error(transparent)]
    TlsClientError(#[from] tls_client::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    InvalidServerName(#[from] InvalidDnsNameError),
    #[error("Prover is already running")]
    AlreadyRunning,
    #[error("Unable to close TLS connection")]
    CloseTlsConnection,
    #[error("server did not send a close_notify")]
    ServerNoCloseNotify,
    #[error("Prover has already been shutdown")]
    AlreadyShutdown,
    #[error("Unable to receive transcripts: {0}")]
    TranscriptError(#[from] Canceled),
}

async fn setup_mpc_backend(
    config: &ProverConfig,
    mut mux: BincodeMux<UidYamuxControl>,
) -> Result<
    (
        MpcTlsLeader,
        DEAPVm<SenderActorControl, ReceiverActorControl>,
        ReceiverActorControl,
        ff::ConverterSender<ff::Gf2_128, SenderActorControl>,
        Pin<Box<dyn FusedFuture<Output = ()> + Send + 'static>>,
    ),
    ProverError,
> {
    let ((mut ot_send, ot_send_fut), (mut ot_recv, ot_recv_fut)) = futures::try_join!(
        create_ot_sender(mux.clone(), config.build_ot_sender_config()),
        create_ot_receiver(mux.clone(), config.build_ot_receiver_config())
    )
    .unwrap();

    // Join the OT background futures so they can be polled together
    let mut ot_fut = Box::pin(join(ot_send_fut, ot_recv_fut).map(|_| ()).fuse());

    futures::select! {
        _ = &mut ot_fut => panic!("OT background task failed"),
        res = try_join(ot_send.setup(), ot_recv.setup()).fuse() => _ = res.unwrap(),
    }

    let mut vm = DEAPVm::new(
        "vm",
        GarbleRole::Leader,
        rand::rngs::OsRng.gen(),
        mux.get_channel("vm").await.unwrap(),
        Box::new(mux.clone()),
        ot_send.clone(),
        ot_recv.clone(),
    );

    let p256_sender_config = config.build_p256_sender_config();
    let channel = mux.get_channel(p256_sender_config.id()).await.unwrap();
    let p256_send =
        ff::ConverterSender::<ff::P256, _>::new(p256_sender_config, ot_send.clone(), channel);

    let p256_receiver_config = config.build_p256_receiver_config();
    let channel = mux.get_channel(p256_receiver_config.id()).await.unwrap();
    let p256_recv =
        ff::ConverterReceiver::<ff::P256, _>::new(p256_receiver_config, ot_recv.clone(), channel);

    let gf2_config = config.build_gf2_config();
    let channel = mux.get_channel(gf2_config.id()).await.unwrap();
    let gf2 = ff::ConverterSender::<ff::Gf2_128, _>::new(gf2_config, ot_send.clone(), channel);

    let mpc_tls_config = config.build_mpc_tls_config();

    let (ke, prf, encrypter, decrypter) = setup_components(
        mpc_tls_config.common(),
        TlsRole::Leader,
        &mut mux,
        &mut vm,
        p256_send,
        p256_recv,
        gf2.handle().unwrap(),
    )
    .await
    .unwrap();

    let channel = mux.get_channel(mpc_tls_config.common().id()).await.unwrap();
    let mpc_tls = MpcTlsLeader::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    Ok((mpc_tls, vm, ot_recv, gf2, ot_fut))
}

/// Runs the TLS session to completion, returning the session transcripts.
async fn run_client<T: AsyncWrite + AsyncRead + Unpin>(
    mut client: ClientConnection,
    server_socket: T,
    transcript_tx: &mut Transcript,
    transcript_rx: &mut Transcript,
    mut tx_receiver: channel::mpsc::Receiver<Bytes>,
    mut rx_sender: channel::mpsc::Sender<Result<Bytes, std::io::Error>>,
    mut close_tls_receiver: channel::oneshot::Receiver<()>,
) -> Result<(), ProverError> {
    client.start().await?;

    let (mut server_rx, mut server_tx) = server_socket.split();

    let mut rx_tls_buf = [0u8; RX_TLS_BUF_SIZE];
    let mut rx_buf = [0u8; RX_BUF_SIZE];

    let mut client_closed = false;
    let mut server_closed = false;

    let mut rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
    loop {
        select_biased! {
            read_res = &mut rx_tls_fut => {
                let received = read_res?;

                // Loop until we've processed all the data we received in this read.
                let mut processed = 0;
                while processed < received {
                    processed += client.read_tls(&mut &rx_tls_buf[processed..received])?;
                    match client.process_new_packets().await {
                        Ok(_) => {}
                        Err(e) => {
                            // In case we have an alert to send describing this error,
                            // try a last-gasp write -- but don't predate the primary
                            // error.
                            let _ignored = client.write_tls_async(&mut server_tx).await;

                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        }
                    }
                }

                if received == 0 {
                    server_closed = true;
                }

                // Reset the read future so next iteration we can read again.
                rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
            }
            data = tx_receiver.select_next_some() => {
                transcript_tx.extend(&data);
                client
                    .write_all_plaintext(&data)
                    .await?;
            },
            _ = &mut close_tls_receiver => {
                client_closed = true;

                client.send_close_notify().await?;

                // Flush all remaining plaintext
                while client.wants_write() {
                    client.write_tls_async(&mut server_tx).await?;
                }
                server_tx.flush().await?;
                server_tx.close().await?;
            },
        }

        while client.wants_write() && !client_closed {
            client.write_tls_async(&mut server_tx).await?;
        }

        // Flush all remaining plaintext to the server
        // otherwise this loop could hang forever as the server
        // waits for more data before responding.
        server_tx.flush().await?;

        // Forward all plaintext to the TLSConnection
        loop {
            let n = match client.reader().read(&mut rx_buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // Some servers will not send a close_notify, in which case we need to
                // error because we can't reveal the MAC key to the Notary.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(ProverError::ServerNoCloseNotify)
                }
                Err(e) => return Err(e)?,
            };

            if n > 0 {
                transcript_rx.extend(&rx_buf[..n]);
                rx_sender
                    .send(Ok(Bytes::copy_from_slice(&rx_buf[..n])))
                    .await
                    .unwrap();
            } else {
                break;
            }
        }

        if client_closed && server_closed {
            break;
        }
    }

    // Extra guard to guarantee that the server sent a close_notify.
    //
    // DO NOT REMOVE!
    //
    // This is necessary, as our protocol reveals the MAC key to the Notary afterwards
    // which could be used to authenticate modified TLS records if the Notary is
    // in the middle of the connection.
    if !client.received_close_notify() {
        return Err(ProverError::ServerNoCloseNotify);
    }

    Ok(())
}
