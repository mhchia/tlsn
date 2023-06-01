use std::pin::Pin;

use actor_ot::{ReceiverActorControl, SenderActorControl};
use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    future::FusedFuture,
};

use mpc_core::{commit::Decommitment, hash::Hash};
use mpc_garble::protocol::deap::DEAPVm;
use mpc_share_conversion::{ConverterSender, Gf2_128};
use tls_core::{dns::ServerName, handshake::HandshakeData, key::PublicKey};
use tlsn_core::{SubstringsCommitment, Transcript};
use uid_mux::{UidYamux, UidYamuxControl};
use utils_aio::{codec::BincodeMux, mux::MuxerError};

pub struct Initialized<S, T> {
    pub(crate) server_name: ServerName,

    pub(crate) server_socket: S,
    pub(crate) muxer: UidYamux<T>,
    pub(crate) mux: BincodeMux<UidYamuxControl>,

    pub(crate) tx_receiver: Receiver<Bytes>,
    pub(crate) rx_sender: Sender<Result<Bytes, std::io::Error>>,
    pub(crate) close_tls_receiver: oneshot::Receiver<()>,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,
}

pub struct Notarizing {
    pub(crate) muxer_fut:
        Pin<Box<dyn FusedFuture<Output = Result<(), MuxerError>> + Send + 'static>>,
    pub(crate) mux: BincodeMux<UidYamuxControl>,

    pub(crate) vm: DEAPVm<SenderActorControl, ReceiverActorControl>,
    pub(crate) ot_fut: Pin<Box<dyn FusedFuture<Output = ()> + Send + 'static>>,
    pub(crate) gf2: ConverterSender<Gf2_128, SenderActorControl>,

    pub(crate) start_time: u64,
    pub(crate) handshake_decommitment: Decommitment<HandshakeData>,
    pub(crate) server_public_key: PublicKey,

    pub(crate) transcript_tx: Transcript,
    pub(crate) transcript_rx: Transcript,

    pub(crate) commitments: Vec<Hash>,
    pub(crate) substring_commitments: Vec<SubstringsCommitment>,
}

impl std::fmt::Debug for Notarizing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notarizing")
            .field("transcript_tx", &self.transcript_tx)
            .field("transcript_rx", &self.transcript_rx)
            .finish()
    }
}

#[derive(Debug)]
pub struct Finalized {}

pub trait ProverState: sealed::Sealed {}

impl<S, T> ProverState for Initialized<S, T> {}
impl ProverState for Notarizing {}
impl ProverState for Finalized {}

mod sealed {
    pub trait Sealed {}
    impl<S, T> Sealed for super::Initialized<S, T> {}
    impl Sealed for super::Notarizing {}
    impl Sealed for super::Finalized {}
}
