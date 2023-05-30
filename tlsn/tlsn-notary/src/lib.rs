pub(crate) mod config;
mod error;

use std::time::{SystemTime, UNIX_EPOCH};

pub use error::NotaryError;

pub use config::{NotaryConfig, NotaryConfigBuilder, NotaryConfigBuilderError};

use futures::{AsyncRead, AsyncWrite, FutureExt, SinkExt, StreamExt};

use actor_ot::{
    create_ot_receiver, create_ot_sender, OTActorReceiverConfig, OTActorSenderConfig,
    ObliviousReveal,
};

use mpc_core::serialize::CanonicalSerialize;
use mpc_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpc_share_conversion as ff;
use rand::Rng;
use signature::Signer;
use tlsn_core::{
    msg::{SignedSessionHeader, TlsnMessage},
    signature::Signature,
    HandshakeSummary, SessionHeader,
};
use tlsn_tls_mpc::{
    setup_components, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig, TlsRole,
};
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, expect_msg_or_err, mux::MuxChannel};

use crate::error::OTShutdownError;

pub struct Notary {
    config: NotaryConfig,
}

impl Notary {
    /// Create a new `Notary`.
    pub fn new(config: NotaryConfig) -> Self {
        Self { config }
    }

    pub async fn run<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static, T>(
        &mut self,
        socket: S,
        signer: &impl Signer<T>,
    ) -> Result<SessionHeader, NotaryError>
    where
        T: Into<Signature>,
    {
        let mut muxer = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Server);
        let mut mux = BincodeMux::new(muxer.control());

        let mut muxer_fut = Box::pin(muxer.run().fuse());

        // Sets up the OT actors
        let ot_fut = async {
            // TODO: calculate number of OTs more accurately
            let ot_send_config = OTActorSenderConfig::builder()
                .id("ot/1")
                .initial_count(self.config.max_transcript_size() * 8)
                .committed()
                .build()
                .unwrap();
            let ot_recv_config = OTActorReceiverConfig::builder()
                .id("ot/0")
                .initial_count(self.config.max_transcript_size() * 8)
                .build()
                .unwrap();

            futures::try_join!(
                create_ot_sender("ot/1", mux.clone(), ot_send_config),
                create_ot_receiver("ot/0", mux.clone(), ot_recv_config)
            )
        };

        let ((mut ot_send, ot_send_fut), (mut ot_recv, ot_recv_fut)) = futures::select! {
            err = muxer_fut => return Err(err.expect_err("muxer runs until connection closes"))?,
            res = ot_fut.fuse() => res.map_err(|err| NotaryError::MpcError(Box::new(err)))?,
        };

        let notarize_fut = async {
            let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();

            futures::try_join!(ot_send.setup(), ot_recv.setup())
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            let mut vm = DEAPVm::new(
                "vm",
                GarbleRole::Follower,
                encoder_seed,
                mux.get_channel("vm").await?,
                Box::new(mux.clone()),
                ot_send.clone(),
                ot_recv.clone(),
            );

            let p256_send = ff::ConverterSender::<ff::P256, _>::new(
                ff::SenderConfig::builder().id("p256/1").build().unwrap(),
                ot_send.clone(),
                mux.get_channel("p256/1").await?,
            );

            let p256_recv = ff::ConverterReceiver::<ff::P256, _>::new(
                ff::ReceiverConfig::builder().id("p256/0").build().unwrap(),
                ot_recv.clone(),
                mux.get_channel("p256/0").await?,
            );

            let mut gf2 = ff::ConverterReceiver::<ff::Gf2_128, _>::new(
                ff::ReceiverConfig::builder()
                    .id("gf2")
                    .record()
                    .build()
                    .unwrap(),
                ot_recv.clone(),
                mux.get_channel("gf2").await?,
            );

            let common_config = MpcTlsCommonConfig::builder().id("test").build().unwrap();
            let (ke, prf, encrypter, decrypter) = setup_components(
                &common_config,
                TlsRole::Follower,
                &mut mux,
                &mut vm,
                p256_send,
                p256_recv,
                gf2.handle()
                    .map_err(|e| NotaryError::MpcError(Box::new(e)))?,
            )
            .await
            .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            let mut mpc_tls = MpcTlsFollower::new(
                MpcTlsFollowerConfig::builder()
                    .common(common_config)
                    .build()
                    .unwrap(),
                mux.get_channel("test").await?,
                ke,
                prf,
                encrypter,
                decrypter,
            );

            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            mpc_tls.run().await?;

            let mut notarize_channel = mux.get_channel("notarize").await?;

            let merkle_root =
                expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

            // Finalize all MPC before signing the session header
            ot_send
                .reveal()
                .await
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;
            vm.finalize()
                .await
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;
            gf2.verify()
                .await
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            // Create, sign and send the session header
            let (sent_len, recv_len) = mpc_tls.bytes_transferred();

            let handshake_summary = HandshakeSummary::new(
                start_time,
                mpc_tls
                    .server_key()
                    .expect("server key is set after session"),
                mpc_tls
                    .handshake_commitment()
                    .expect("handshake commitment is set after session"),
            );

            let session_header = SessionHeader::new(
                encoder_seed,
                merkle_root,
                sent_len as u32,
                recv_len as u32,
                handshake_summary,
            );

            let signature = signer.sign(&session_header.to_bytes());

            notarize_channel
                .send(TlsnMessage::SignedSessionHeader(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
                }))
                .await?;

            Ok::<_, NotaryError>(session_header)
        };

        let session_header = futures::select! {
            err = muxer_fut => return Err(err.expect_err("muxer runs until connection closes"))?,
            _ = ot_send_fut.fuse() => return Err(OTShutdownError)?,
            _ = ot_recv_fut.fuse() => return Err(OTShutdownError)?,
            res = notarize_fut.fuse() => res?,
        };

        Ok(session_header)
    }
}
