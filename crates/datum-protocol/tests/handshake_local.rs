//! Hermetic mock-pool handshake round-trip.
//!
//! Spins up a local TCP listener that plays the role of OCEAN's pool:
//! generates its own pool keypair, accepts the client hello, decrypts it,
//! verifies the embedded Ed25519 signature, then constructs the structured
//! response (4 echoed pubkeys + 2 pool session pubkeys + MOTD), seals it to
//! the client's session X25519 pubkey, and sends it framed with the receiver
//! header XOR chain.
//!
//! With this green, the wire format is provably symmetric under our own
//! implementation — i.e. every byte we'd ship to OCEAN parses back if OCEAN
//! ran our same code. Live OCEAN compatibility still has to be confirmed
//! separately by `handshake_probe` against the real endpoint, but this rules
//! out the entire class of "we wrote both sides wrong in the same way" bugs
//! when paired with the byte-level tests in handshake.rs.

use datum_protocol::{
    build_hello_payload, datum_header_xor_feedback, frame_for_hello, parse_received_header,
    seal_hello, ClientKeypairs, DatumCrypto, DryocCrypto, FrameHeader, HeaderObfuscator, ProtoCmd,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn full_handshake_round_trip() {
    let crypto = DryocCrypto;
    let (pool_lt_x_pub, pool_lt_x_sec) = crypto.box_keypair();
    let (pool_session_ed_pub, _pool_session_ed_sec) = crypto.sign_keypair();
    let (pool_session_x_pub, _pool_session_x_sec) = crypto.box_keypair();
    let motd = "datum-rs hermetic mock pool";

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_pool_lt_x_pub = pool_lt_x_pub;
    let server_pool_lt_x_sec = pool_lt_x_sec;
    let server_pool_session_ed_pub = pool_session_ed_pub;
    let server_pool_session_x_pub = pool_session_x_pub;
    let server_motd = motd.to_string();

    let server = tokio::spawn(async move {
        let crypto = DryocCrypto;
        let (sock, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = sock.into_split();

        let mut header_buf = [0u8; 4];
        rd.read_exact(&mut header_buf).await.unwrap();
        let mut server_recv_obf = HeaderObfuscator::initial_sender();
        let header = parse_received_header(&mut server_recv_obf, header_buf).unwrap();
        assert!(header.is_signed);
        assert!(header.is_encrypted_pubkey);

        let mut sealed = vec![0u8; header.cmd_len as usize];
        rd.read_exact(&mut sealed).await.unwrap();

        let plaintext = crypto
            .box_seal_open(&sealed, &server_pool_lt_x_pub, &server_pool_lt_x_sec)
            .expect("server unseal hello");

        let sig_offset = plaintext.len() - 64;
        let signed_part = &plaintext[..sig_offset];
        let signature: [u8; 64] = plaintext[sig_offset..].try_into().unwrap();
        let client_lt_ed_pub: [u8; 32] = plaintext[0..32].try_into().unwrap();
        let client_lt_x_pub: [u8; 32] = plaintext[32..64].try_into().unwrap();
        let client_s_ed_pub: [u8; 32] = plaintext[64..96].try_into().unwrap();
        let client_s_x_pub: [u8; 32] = plaintext[96..128].try_into().unwrap();
        crypto
            .verify_detached(signed_part, &signature, &client_lt_ed_pub)
            .expect("server verify hello signature");

        // Per datum_protocol.c:1002-1018: version + client_id are written
        // back-to-back with no NUL between them; a single NUL terminates
        // the whole text section before the 0xFE sentinel.
        let nul = plaintext[128..].iter().position(|&b| b == 0).unwrap();
        let after_text = 128 + nul + 1;
        assert_eq!(plaintext[after_text], 0xFE);
        let nk_offset = after_text + 1;
        let nk = u32::from_le_bytes(plaintext[nk_offset..nk_offset + 4].try_into().unwrap());

        let mut response = Vec::with_capacity(192 + server_motd.len() + 1);
        response.extend_from_slice(&client_lt_ed_pub);
        response.extend_from_slice(&client_lt_x_pub);
        response.extend_from_slice(&client_s_ed_pub);
        response.extend_from_slice(&client_s_x_pub);
        response.extend_from_slice(&server_pool_session_ed_pub);
        response.extend_from_slice(&server_pool_session_x_pub);
        response.extend_from_slice(server_motd.as_bytes());
        response.push(0);

        let sealed_resp = crypto
            .box_seal(&client_s_x_pub, &response)
            .expect("server seal response");

        let resp_header = FrameHeader {
            cmd_len: sealed_resp.len() as u32,
            is_signed: false,
            is_encrypted_pubkey: true,
            is_encrypted_channel: false,
            proto_cmd: 0x02,
        };
        let raw_resp_header = resp_header.pack().unwrap();
        let resp_word = u32::from_le_bytes(raw_resp_header);
        let server_send_key = datum_header_xor_feedback(!nk);
        let xored_word = resp_word ^ server_send_key;
        wr.write_all(&xored_word.to_le_bytes()).await.unwrap();
        wr.write_all(&sealed_resp).await.unwrap();
    });

    let client_crypto = DryocCrypto;
    let client_keys = ClientKeypairs::generate(&client_crypto);
    let nk: u32 = 0x1234_5678;
    let padding = vec![0xAAu8; 64];
    let plaintext = build_hello_payload(
        &client_crypto,
        &client_keys,
        "v0.4.1-beta",
        "/datum-rs hermetic-test",
        nk,
        &padding,
    )
    .unwrap();
    let sealed = seal_hello(&client_crypto, &plaintext, &pool_lt_x_pub).unwrap();
    let framed = frame_for_hello(&sealed).unwrap();

    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = stream.into_split();
    wr.write_all(&framed).await.unwrap();

    let mut resp_header_buf = [0u8; 4];
    rd.read_exact(&mut resp_header_buf).await.unwrap();
    let mut client_recv_obf = HeaderObfuscator::for_receiver(nk);
    let resp_header = parse_received_header(&mut client_recv_obf, resp_header_buf).unwrap();

    let response_cmd = ProtoCmd::from_bits(resp_header.proto_cmd);
    assert!(matches!(response_cmd, ProtoCmd::Pong));

    let mut sealed_resp = vec![0u8; resp_header.cmd_len as usize];
    rd.read_exact(&mut sealed_resp).await.unwrap();

    let response_plaintext = client_crypto
        .box_seal_open(
            &sealed_resp,
            &client_keys.session_x25519_pub,
            &client_keys.session_x25519_sec,
        )
        .expect("client unseal response");

    assert_eq!(
        &response_plaintext[0..32],
        &client_keys.long_term_ed25519_pub[..]
    );
    assert_eq!(
        &response_plaintext[32..64],
        &client_keys.long_term_x25519_pub[..]
    );
    assert_eq!(
        &response_plaintext[64..96],
        &client_keys.session_ed25519_pub[..]
    );
    assert_eq!(
        &response_plaintext[96..128],
        &client_keys.session_x25519_pub[..]
    );
    assert_eq!(&response_plaintext[128..160], &pool_session_ed_pub[..]);
    assert_eq!(&response_plaintext[160..192], &pool_session_x_pub[..]);
    let motd_bytes = &response_plaintext[192..];
    let motd_end = motd_bytes.iter().position(|&b| b == 0).unwrap();
    assert_eq!(&motd_bytes[..motd_end], motd.as_bytes());

    server.await.unwrap();
}
