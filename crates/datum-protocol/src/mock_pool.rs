//! In-tree mock DATUM pool.
//!
//! Provides a `MockPool` that listens on a TCP port, completes the encrypted
//! handshake against any client following our [`crate::handshake`] format,
//! and answers a few canned post-handshake messages. Used by hermetic tests
//! across the workspace; safe to import from any crate that depends on
//! `datum-protocol` because no live network is involved.
//!
//! What it does **not** do (yet): full client-config push, share-response
//! cycling, block-notify pushes. The runtime crates that need those add them
//! at-call when their integration tests cover the relevant path.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::crypto::{DatumCrypto, DryocCrypto};
use crate::frame::FrameHeader;
use crate::handshake::parse_received_header;
use crate::obfuscation::{datum_header_xor_feedback, HeaderObfuscator};

pub struct MockPool {
    pub addr: std::net::SocketAddr,
    pub long_term_x25519_pub: [u8; 32],
    pub long_term_x25519_sec: [u8; 32],
    pub session_ed25519_pub: [u8; 32],
    pub session_x25519_pub: [u8; 32],
    pub motd: String,
}

impl MockPool {
    /// Spawn the mock pool. The returned `MockPool` reports the bound address
    /// and the long-term + session pubkeys the client should use.
    /// Pass `MockPool.long_term_x25519_pub` to `seal_hello` and
    /// `MockPool.addr` to `TcpStream::connect`.
    pub async fn spawn() -> Arc<Self> {
        let crypto = DryocCrypto;
        let (lt_pub, lt_sec) = crypto.box_keypair();
        let (s_ed_pub, _) = crypto.sign_keypair();
        let (s_x_pub, s_x_sec) = crypto.box_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pool = Arc::new(MockPool {
            addr,
            long_term_x25519_pub: lt_pub,
            long_term_x25519_sec: lt_sec,
            session_ed25519_pub: s_ed_pub,
            session_x25519_pub: s_x_pub,
            motd: "datum-rs in-tree mock pool".to_string(),
        });

        let pool_for_task = pool.clone();
        let pool_session_x_sec = s_x_sec;
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let pool = pool_for_task.clone();
                tokio::spawn(handle_connection(sock, pool, pool_session_x_sec));
            }
        });

        pool
    }
}

async fn handle_connection(
    mut sock: tokio::net::TcpStream,
    pool: Arc<MockPool>,
    _pool_session_x_sec: [u8; 32],
) {
    let crypto = DryocCrypto;
    let (rd, wr) = sock.split();
    let mut rd = rd;
    let mut wr = wr;

    let mut header_buf = [0u8; 4];
    if rd.read_exact(&mut header_buf).await.is_err() {
        return;
    }
    let mut server_recv_obf = HeaderObfuscator::initial_sender();
    let header = parse_received_header(&mut server_recv_obf, header_buf).unwrap();
    if header.cmd_len == 0 || header.cmd_len > 1_048_576 {
        return;
    }

    let mut sealed = vec![0u8; header.cmd_len as usize];
    if rd.read_exact(&mut sealed).await.is_err() {
        return;
    }
    let plaintext = match crypto.box_seal_open(
        &sealed,
        &pool.long_term_x25519_pub,
        &pool.long_term_x25519_sec,
    ) {
        Ok(p) => p,
        Err(_) => return,
    };

    if plaintext.len() < 128 + 64 {
        return;
    }
    let client_lt_ed_pub: [u8; 32] = plaintext[0..32].try_into().unwrap();
    let client_lt_x_pub: [u8; 32] = plaintext[32..64].try_into().unwrap();
    let client_s_ed_pub: [u8; 32] = plaintext[64..96].try_into().unwrap();
    let client_s_x_pub: [u8; 32] = plaintext[96..128].try_into().unwrap();
    let sig_offset = plaintext.len() - 64;
    let signed_part = &plaintext[..sig_offset];
    let signature: [u8; 64] = plaintext[sig_offset..].try_into().unwrap();
    if crypto
        .verify_detached(signed_part, &signature, &client_lt_ed_pub)
        .is_err()
    {
        return;
    }

    // Find the single NUL terminator after the text section, then 0xFE
    // sentinel, then nk.
    let nk = match find_nk(&plaintext, 128) {
        Some(v) => v,
        None => return,
    };

    let mut response = Vec::new();
    response.extend_from_slice(&client_lt_ed_pub);
    response.extend_from_slice(&client_lt_x_pub);
    response.extend_from_slice(&client_s_ed_pub);
    response.extend_from_slice(&client_s_x_pub);
    response.extend_from_slice(&pool.session_ed25519_pub);
    response.extend_from_slice(&pool.session_x25519_pub);
    response.extend_from_slice(pool.motd.as_bytes());
    response.push(0);

    let sealed_resp = crypto.box_seal(&client_s_x_pub, &response).unwrap();
    let resp_header = FrameHeader {
        cmd_len: sealed_resp.len() as u32,
        is_signed: false,
        is_encrypted_pubkey: true,
        is_encrypted_channel: false,
        proto_cmd: 0x02,
    };
    let raw = resp_header.pack().unwrap();
    let resp_word = u32::from_le_bytes(raw);
    let server_send_key = datum_header_xor_feedback(!nk);
    let xored = resp_word ^ server_send_key;
    let _ = wr.write_all(&xored.to_le_bytes()).await;
    let _ = wr.write_all(&sealed_resp).await;
    // Keep the connection alive until the client closes — matches the real
    // pool's behavior post-handshake.
    let _ = wr.flush().await;
    let mut buf = [0u8; 64];
    while rd.read(&mut buf).await.is_ok() {}
}

fn find_nk(plaintext: &[u8], text_start: usize) -> Option<u32> {
    let nul_offset = plaintext[text_start..].iter().position(|&b| b == 0)?;
    let after_text = text_start + nul_offset + 1;
    if plaintext.get(after_text) != Some(&0xFE) {
        return None;
    }
    let nk_offset = after_text + 1;
    if plaintext.len() < nk_offset + 4 {
        return None;
    }
    Some(u32::from_le_bytes(
        plaintext[nk_offset..nk_offset + 4].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{build_hello_payload, frame_for_hello, seal_hello, ClientKeypairs};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn mock_pool_completes_handshake() {
        let pool = MockPool::spawn().await;

        let crypto = DryocCrypto;
        let keys = ClientKeypairs::generate(&crypto);
        let nk: u32 = 0xfeed_face;
        let plaintext = build_hello_payload(
            &crypto,
            &keys,
            "v0.4.1-beta",
            "/datum-rs mock_pool test",
            nk,
            &[0xAAu8; 32],
        )
        .unwrap();
        let sealed = seal_hello(&crypto, &plaintext, &pool.long_term_x25519_pub).unwrap();
        let framed = frame_for_hello(&sealed).unwrap();

        let mut stream = TcpStream::connect(pool.addr).await.unwrap();
        let (mut rd, mut wr) = stream.split();
        wr.write_all(&framed).await.unwrap();

        let mut header = [0u8; 4];
        rd.read_exact(&mut header).await.unwrap();
        let mut recv_obf = HeaderObfuscator::for_receiver(nk);
        let h = parse_received_header(&mut recv_obf, header).unwrap();
        assert!(h.cmd_len > 0);

        let mut resp = vec![0u8; h.cmd_len as usize];
        rd.read_exact(&mut resp).await.unwrap();
        let plaintext_resp = crypto
            .box_seal_open(&resp, &keys.session_x25519_pub, &keys.session_x25519_sec)
            .unwrap();
        assert_eq!(&plaintext_resp[0..32], &keys.long_term_ed25519_pub[..]);
        assert_eq!(&plaintext_resp[160..192], &pool.session_x25519_pub[..]);
        let motd_section = &plaintext_resp[192..];
        let nul = motd_section.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&motd_section[..nul], pool.motd.as_bytes());
    }
}
