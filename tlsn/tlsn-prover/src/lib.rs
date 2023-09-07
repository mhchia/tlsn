//! The prover library
//!
//! This library provides the [Prover] type. It can be used for creating TLS connections with a
//! server which can be notarized with the help of a notary.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod state;

pub use config::ProverConfig;
pub use error::ProverError;
pub use state::{Initialized, Notarize, ProverState};

use futures::{
    future::{join, try_join, FusedFuture},
    AsyncRead, AsyncWrite, Future, FutureExt, SinkExt, StreamExt,
};
use rand::Rng;
use tracing::info;
use std::{ops::Range, pin::Pin, sync::Arc};
use tls_client_async::{bind_client, ClosedConnection, TlsConnection};
use tls_mpc::{setup_components, MpcTlsLeader, TlsRole};

use actor_ot::{create_ot_receiver, create_ot_sender, ReceiverActorControl, SenderActorControl};
use mpz_core::commit::HashCommit;
use mpz_garble::{
    config::Role as GarbleRole,
    protocol::deap::{DEAPVm, PeerEncodings},
};
use mpz_share_conversion as ff;
use tls_client::{ClientConnection, ServerName};
use tlsn_core::{
    commitment::Blake3,
    merkle::MerkleTree,
    msg::{SignedSessionHeader, TlsnMessage},
    transcript::Transcript,
    Direction, NotarizedSession, SessionData, SubstringsCommitment, SubstringsCommitmentSet,
};
use uid_mux::{yamux, UidYamux, UidYamuxControl};
use utils_aio::{codec::BincodeMux, expect_msg_or_err, mux::MuxChannelSerde};
use web_time;

use crate::error::OTShutdownError;

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

/// Helper function to bind a new prover to the given sockets.
///
/// Returns a handle to the TLS connection, a future which returns the prover once the connection is
/// closed, and a future which must be polled for the connection to the Notary to make progress.
///
/// # Arguments
///
/// * `config` - The configuration for the prover.
/// * `client_socket` - The socket to the server.
/// * `notary_socket` - The socket to the notary.
#[allow(clippy::type_complexity)]
// #[cfg_attr(
//     feature = "tracing",
//     instrument(level = "info", skip(client_socket, notary_socket), err)
// )]
pub async fn bind_prover<
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
>(
    config: ProverConfig,
    client_socket: S,
    notary_socket: T,
) -> Result<
    (
        TlsConnection,
        ConnectionFuture<BincodeMux<UidYamuxControl>>,
        MuxFuture,
    ), // (tls_connection, prover_future, notary_future)
    ProverError,
> {
    info!("!@# bind_prover: 0");
    let mut mux = UidYamux::new(yamux::Config::default(), notary_socket, yamux::Mode::Client);
    info!("!@# bind_prover: 1");
    let mux_control = BincodeMux::new(mux.control());
    info!("!@# bind_prover: 2");

    let mut mux_fut = MuxFuture {
        fut: Box::pin(async move { mux.run().await.map_err(ProverError::from) }),
    };
    info!("!@# bind_prover: 3");

    let prover_fut = Prover::new(config, mux_control)?.bind_prover(client_socket);
    info!("!@# bind_prover: 4");
    let (conn, conn_fut) = futures::select! {
        res = prover_fut.fuse() => match res {
            Ok(result) => result,
            Err(e) => {
                info!("!@# Error in prover_fut: {:?}", e);
                return Err(e.into());
            }
        },
        // mux_fut is fused, so this branch is only taken if the mux_fut is done
        res2 = (&mut mux_fut).fuse() => match res2 {
            Ok(_) => {
                info!("!@# mux_fut completed without error");
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            },
            Err(e) => {
                info!("!@# Error in mux_fut: {:?}", e);
                return Err(e.into());
            }
        }
    };

    info!("!@# bind_prover: 5");

    Ok((conn, conn_fut, mux_fut))
}

/// Multiplexer future which must be polled to make progress.
pub struct MuxFuture {
    fut: Pin<Box<dyn Future<Output = Result<(), ProverError>> + Send + 'static>>,
}

impl Future for MuxFuture {
    type Output = Result<(), ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

/// TLS connection future which must be polled for the connection to make progress.
pub struct ConnectionFuture<T> {
    #[allow(clippy::type_complexity)]
    fut: Pin<Box<dyn Future<Output = Result<Prover<Notarize<T>>, ProverError>> + Send + 'static>>,
}

impl<T> Future for ConnectionFuture<T> {
    type Output = Result<Prover<Notarize<T>>, ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: ProverState> {
    config: ProverConfig,
    state: T,
}

impl<T> Prover<Initialized<T>>
where
    T: MuxChannelSerde + Clone + Send + Sync + Unpin + 'static,
{
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    /// * `notary_mux` - The multiplexed connection to the notary.
    pub fn new(config: ProverConfig, notary_mux: T) -> Result<Self, ProverError> {
        let server_name = ServerName::try_from(config.server_dns())?;

        Ok(Self {
            config,
            state: Initialized {
                server_name,
                notary_mux,
            },
        })
    }

    /// Binds the prover to the provided socket.
    // #[cfg_attr(
    //     feature = "tracing",
    //     instrument(level = "debug", skip(self, socket), err)
    // )]
    pub async fn bind_prover<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(TlsConnection, ConnectionFuture<T>), ProverError> {
        let Initialized {
            server_name,
            notary_mux: mux,
        } = self.state;

        info!("!@# Prover.bind_prover: 0");
        let (mpc_tls, vm, _, gf2, mut ot_fut) =
            setup_mpc_backend(&self.config, mux.clone()).await?;
        info!("!@# Prover.bind_prover: 1");

        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.config.root_cert_store.clone())
            .with_no_client_auth();
        info!("!@# Prover.bind_prover: 2");

        let client = ClientConnection::new(Arc::new(config), Box::new(mpc_tls), server_name)?;
        info!("!@# Prover.bind_prover: 3");

        let (conn, conn_fut) = bind_client(socket, client);
        info!("!@# Prover.bind_prover: 4");

        let start_time = web_time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        info!("!@# Prover.bind_prover: 5");

        let fut = Box::pin({
            info!("!@# Prover.bind_prover: 6");
            #[allow(clippy::let_and_return)]
            let fut = async move {
                info!("!@# Prover.bind_prover: 7");
                let ClosedConnection {
                    mut client,
                    sent,
                    recv,
                } = futures::select! {
                    res = conn_fut.fuse() => {
                        info!("!@# Prover.bind_prover: 5");
                        res.unwrap()
                    },
                    _ = ot_fut => return Err(OTShutdownError)?,
                };
                info!("!@# Prover.bind_prover: 8");

                // Extra guard to guarantee that the server sent a close_notify.
                //
                // DO NOT REMOVE!
                //
                // This is necessary, as our protocol reveals the MAC key to the Notary afterwards
                // which could be used to authenticate modified TLS records if the Notary is
                // in the middle of the connection.
                if !client.received_close_notify() {
                    info!("!@# Prover.bind_prover: 9");
                    return Err(ProverError::ServerNoCloseNotify);
                }
                info!("!@# Prover.bind_prover: 10");

                let backend = client
                    .backend_mut()
                    .as_any_mut()
                    .downcast_mut::<MpcTlsLeader>()
                    .unwrap();
                info!("!@# Prover.bind_prover: 11");

                let handshake_decommitment = backend
                    .handshake_decommitment_mut()
                    .take()
                    .expect("handshake decommitment is set");
                info!("!@# Prover.bind_prover: 12");
                let server_public_key = backend
                    .server_public_key()
                    .cloned()
                    .expect("server public key is set");
                info!("!@# Prover.bind_prover: 13");

                Ok(Prover {
                    config: self.config,
                    state: Notarize {
                        notary_mux: mux,
                        vm,
                        ot_fut,
                        gf2,
                        start_time,
                        handshake_decommitment,
                        server_public_key,
                        transcript_tx: Transcript::new("tx", sent),
                        transcript_rx: Transcript::new("rx", recv),
                        commitments: Vec::default(),
                        substring_commitments: Vec::default(),
                    },
                })
            };
            info!("!@# Prover.bind_prover: 14");
            #[cfg(feature = "tracing")]
            let fut = fut.instrument(debug_span!("prover_tls_connection"));
            info!("!@# Prover.bind_prover: 15");
            fut
        });

        Ok((conn, ConnectionFuture { fut }))
    }
}

impl<T> Prover<Notarize<T>>
where
    T: MuxChannelSerde + Clone + Send + Sync + Unpin + 'static,
{
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Add a commitment to the sent requests
    pub fn add_commitment_sent(&mut self, range: Range<u32>) -> Result<(), ProverError> {
        self.add_commitment(range, Direction::Sent)
    }

    /// Add a commitment to the received responses
    pub fn add_commitment_recv(&mut self, range: Range<u32>) -> Result<(), ProverError> {
        self.add_commitment(range, Direction::Received)
    }

    #[cfg_attr(
        feature = "tracing",
        instrument(level = "debug", skip(self, range), err)
    )]
    fn add_commitment(
        &mut self,
        range: Range<u32>,
        direction: Direction,
    ) -> Result<(), ProverError> {
        let ids = match direction {
            Direction::Sent => self.state.transcript_tx.get_ids(&range),
            Direction::Received => self.state.transcript_rx.get_ids(&range),
        };

        let id_refs: Vec<_> = ids.iter().map(|id| id.as_str()).collect();

        let encodings = self
            .state
            .vm
            .get_peer_encodings(&id_refs)
            .map_err(|e| ProverError::MpcError(Box::new(e)))?;

        let (decommitment, commitment) = encodings.hash_commit();

        self.state.commitments.push(commitment);

        let commitment = Blake3::new(commitment).into();

        let commitment = SubstringsCommitment::new(
            self.state.substring_commitments.len() as u32,
            commitment,
            vec![range],
            direction,
            *decommitment.nonce(),
        );

        self.state.substring_commitments.push(commitment);

        Ok(())
    }

    /// Finalize the notarization returning a [`NotarizedSession`]
    #[cfg_attr(feature = "tracing", instrument(level = "info", skip(self), err))]
    pub async fn finalize(self) -> Result<NotarizedSession, ProverError> {
        let Notarize {
            notary_mux: mut mux,
            mut vm,
            mut ot_fut,
            mut gf2,
            start_time,
            handshake_decommitment,
            server_public_key,
            transcript_tx,
            transcript_rx,
            commitments,
            substring_commitments,
        } = self.state;

        let merkle_tree = MerkleTree::from_leaves(&commitments)?;
        let merkle_root = merkle_tree.root();

        let notarize_fut = async move {
            let mut channel = mux.get_channel("notarize").await?;

            channel
                .send(TlsnMessage::TranscriptCommitmentRoot(merkle_root))
                .await?;

            let notary_encoder_seed = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            let signed_header = expect_msg_or_err!(channel, TlsnMessage::SignedSessionHeader)?;

            Ok::<_, ProverError>((notary_encoder_seed, signed_header))
        };

        let (notary_encoder_seed, SignedSessionHeader { header, signature }) = futures::select! {
            _ = ot_fut => return Err(OTShutdownError)?,
            res = notarize_fut.fuse() => res?,
        };

        // Check the header is consistent with the Prover's view
        header.verify(
            start_time,
            &server_public_key,
            &merkle_tree.root(),
            &notary_encoder_seed,
            &handshake_decommitment,
        )?;

        let commitments = SubstringsCommitmentSet::new(substring_commitments);

        let data = SessionData::new(
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
            merkle_tree,
            commitments,
        );

        Ok(NotarizedSession::new(header, Some(signature), data))
    }
}

// #[cfg_attr(feature = "tracing", instrument(level = "debug", skip(mux), err))]
#[allow(clippy::type_complexity)]
async fn setup_mpc_backend<M: MuxChannelSerde + Clone + Send + 'static>(
    config: &ProverConfig,
    mut mux: M,
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
    #[cfg(feature = "tracing")]
    debug!("!@# setup_mpc_backend: 0");

    #[cfg(feature = "tracing")]
    let (create_ot_sender, create_ot_receiver) = {
        debug!("Starting OT setup");
        let res = (
            |mux: M, config| create_ot_sender(mux, config).in_current_span(),
            |mux: M, config| create_ot_receiver(mux, config).in_current_span(),
        );

        debug!("!@# setup_mpc_backend: 1");
        res
    };

    #[cfg(feature = "tracing")]
    debug!("!@# setup_mpc_backend: 2");

    let ((mut ot_send, ot_send_fut), (mut ot_recv, ot_recv_fut)) = futures::try_join!(
        create_ot_sender(mux.clone(), config.build_ot_sender_config()),
        create_ot_receiver(mux.clone(), config.build_ot_receiver_config())
    )
    .map_err(|e| ProverError::MpcError(Box::new(e)))?;
    #[cfg(feature = "tracing")]
    debug!("!@# setup_mpc_backend: 3");

    // Join the OT background futures so they can be polled together
    // FIXME: stuck here
    let mut ot_fut = Box::pin(join(ot_send_fut, ot_recv_fut).map(|_| ()).fuse());
    #[cfg(feature = "tracing")]
    debug!("!@# setup_mpc_backend: 4");

    futures::select! {
        _ = &mut ot_fut => return Err(OTShutdownError)?,
        res = try_join(ot_send.setup(), ot_recv.setup()).fuse() =>
            _ = res.map_err(|e| ProverError::MpcError(Box::new(e)))?,
    }
    #[cfg(feature = "tracing")]
    debug!("!@# setup_mpc_backend: 5");

    #[cfg(feature = "tracing")]
    debug!("OT setup complete");

    let mut vm = DEAPVm::new(
        "vm",
        GarbleRole::Leader,
        rand::rngs::OsRng.gen(),
        mux.get_channel("vm").await?,
        Box::new(mux.clone()),
        ot_send.clone(),
        ot_recv.clone(),
    );

    let p256_sender_config = config.build_p256_sender_config();
    let channel = mux.get_channel(p256_sender_config.id()).await?;
    let p256_send =
        ff::ConverterSender::<ff::P256, _>::new(p256_sender_config, ot_send.clone(), channel);

    let p256_receiver_config = config.build_p256_receiver_config();
    let channel = mux.get_channel(p256_receiver_config.id()).await?;
    let p256_recv =
        ff::ConverterReceiver::<ff::P256, _>::new(p256_receiver_config, ot_recv.clone(), channel);

    let gf2_config = config.build_gf2_config();
    let channel = mux.get_channel(gf2_config.id()).await?;
    let gf2 = ff::ConverterSender::<ff::Gf2_128, _>::new(gf2_config, ot_send.clone(), channel);

    let mpc_tls_config = config.build_mpc_tls_config();

    let (ke, prf, encrypter, decrypter) = setup_components(
        mpc_tls_config.common(),
        TlsRole::Leader,
        &mut mux,
        &mut vm,
        p256_send,
        p256_recv,
        gf2.handle()
            .map_err(|e| ProverError::MpcError(Box::new(e)))?,
    )
    .await
    .map_err(|e| ProverError::MpcError(Box::new(e)))?;

    let channel = mux.get_channel(mpc_tls_config.common().id()).await?;
    let mpc_tls = MpcTlsLeader::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    #[cfg(feature = "tracing")]
    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_recv, gf2, ot_fut))
}
