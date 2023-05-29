use std::{io::Read, sync::Arc};

use actor_ot::{
    create_ot_pair, create_ot_receiver, create_ot_sender, OTActorReceiverConfig,
    OTActorSenderConfig, ObliviousReveal,
};
use futures::{AsyncRead, AsyncWrite};
use mpc_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpc_share_conversion as ff;
use tlsn_notary::{Notary, NotaryConfig};
use tlsn_tls_mpc::{
    setup_components, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig, MpcTlsLeader,
    MpcTlsLeaderConfig, TlsRole,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, mux::MuxChannel};

#[tokio::test]
async fn test() {
    let (leader_socket, follower_socket) = tokio::io::duplex(2 << 25);

    let config = NotaryConfig::builder().build().unwrap();
    let mut notary = Notary::new(config);

    let (_, notary_res) = tokio::join!(
        prover(leader_socket.compat()),
        notary.run(follower_socket.compat(), todo!())
    );

    notary_res.unwrap();
}

async fn prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: S) {
    let mut leader_mux = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Client);

    let leader_mux_control = leader_mux.control();

    tokio::spawn(async move { leader_mux.run().await.unwrap() });

    let mut leader_mux = BincodeMux::new(leader_mux_control);

    let leader_ot_send_config = OTActorSenderConfig::builder()
        .id("ot/0")
        .initial_count(200_000)
        .build()
        .unwrap();

    let leader_ot_recv_config = OTActorReceiverConfig::builder()
        .id("ot/1")
        .initial_count(200_000)
        .committed()
        .build()
        .unwrap();

    let ((mut leader_ot_send, leader_ot_send_fut), (mut leader_ot_recv, leader_ot_recv_fut)) =
        futures::try_join!(
            create_ot_sender("ot/0", leader_mux.clone(), leader_ot_send_config),
            create_ot_receiver("ot/1", leader_mux.clone(), leader_ot_recv_config)
        )
        .unwrap();

    tokio::spawn(async {
        leader_ot_send_fut.await;
        println!("prover ot send finished")
    });
    tokio::spawn(async {
        leader_ot_recv_fut.await;
        println!("prover ot recv finished")
    });

    println!("prover start ot setup");

    tokio::try_join!(leader_ot_send.setup(), leader_ot_recv.setup(),).unwrap();

    println!("prover ot setup done");

    let mut leader_vm = DEAPVm::new(
        "vm",
        GarbleRole::Leader,
        [0u8; 32],
        leader_mux.get_channel("vm").await.unwrap(),
        Box::new(leader_mux.clone()),
        leader_ot_send.clone(),
        leader_ot_recv.clone(),
    );

    let leader_p256_send = ff::ConverterSender::<ff::P256, _>::new(
        ff::SenderConfig::builder().id("p256/0").build().unwrap(),
        leader_ot_send.clone(),
        leader_mux.get_channel("p256/0").await.unwrap(),
    );

    let leader_p256_recv = ff::ConverterReceiver::<ff::P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/1").build().unwrap(),
        leader_ot_recv.clone(),
        leader_mux.get_channel("p256/1").await.unwrap(),
    );

    let mut leader_gf2 = ff::ConverterSender::<ff::Gf2_128, _>::new(
        ff::SenderConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        leader_ot_send.clone(),
        leader_mux.get_channel("gf2").await.unwrap(),
    );

    let common_config = MpcTlsCommonConfig::builder().id("test").build().unwrap();

    let (leader_ke, leader_prf, leader_encrypter, leader_decrypter) = setup_components(
        &common_config,
        TlsRole::Leader,
        &mut leader_mux,
        &mut leader_vm,
        leader_p256_send,
        leader_p256_recv,
        leader_gf2.handle().unwrap(),
    )
    .await
    .unwrap();

    let leader = MpcTlsLeader::new(
        MpcTlsLeaderConfig::builder()
            .common(common_config.clone())
            .build()
            .unwrap(),
        leader_mux.get_channel("test").await.unwrap(),
        leader_ke,
        leader_prf,
        leader_encrypter,
        leader_decrypter,
    );

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

    let server_name = "httpbin.org".try_into().unwrap();
    let mut conn =
        tls_client::ClientConnection::new(Arc::new(config), Box::new(leader), server_name).unwrap();
    let mut sock = std::net::TcpStream::connect("httpbin.org:443").unwrap();

    let msg = concat!(
        "GET /get HTTP/1.1\r\n",
        "Host: httpbin.org\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "\r\n"
    );

    conn.start().await.unwrap();
    conn.write_plaintext(msg.as_bytes()).await.unwrap();

    while conn.is_handshaking() {
        conn.complete_io(&mut sock).await.unwrap();
    }

    loop {
        if conn.wants_write() {
            conn.write_tls(&mut sock).unwrap();
        }

        if conn.wants_read() {
            let nbyte = conn.read_tls(&mut sock).unwrap();
            if nbyte > 0 {
                conn.process_new_packets().await.unwrap();
            }
        }

        let mut buf = vec![0u8; 1024];
        if let Ok(read) = conn.reader().read(&mut buf) {
            if read > 0 {
                println!("{}", String::from_utf8_lossy(&buf));
            } else {
                break;
            }
        }
    }
    conn.send_close_notify().await.unwrap();
    loop {
        if conn.wants_write() {
            conn.write_tls(&mut sock).unwrap();
        } else {
            break;
        }
    }

    let (finalize_res, reveal_res) = tokio::join!(leader_vm.finalize(), leader_gf2.reveal());

    finalize_res.unwrap();
    reveal_res.unwrap();
}
