use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

pub const CRYPTO_MODE: &str = "dh-sha256-stream-v1";

const DH_PRIME: u128 = u128::MAX >> 1;
const DH_GENERATOR: u128 = 5;
const TRANSFER_CONTEXT: &[u8] = b"file-sharer-transfer-v2";
const CIPHER_CONTEXT: &[u8] = b"file-sharer-cipher-v2";
const MAC_CONTEXT: &[u8] = b"file-sharer-mac-v2";

#[derive(Clone)]
pub struct KeyPair {
    private: u128,
    public: u128,
    public_header: String,
}

pub struct SenderSession {
    pub sender_public_header: String,
    pub nonce_header: String,
    pub crypto: TransferCrypto,
}

#[derive(Clone)]
pub struct TransferCrypto {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    nonce: [u8; 16],
}

pub struct StreamCipher {
    key: [u8; 32],
    nonce: [u8; 16],
    counter: u32,
    block: [u8; 64],
    block_index: usize,
}

pub struct HmacSha256 {
    inner: Sha256,
    outer_key: [u8; 64],
}

impl KeyPair {
    pub fn generate() -> Result<Self, String> {
        let private = random_private()?;
        let public = dh_public(private);
        Ok(Self {
            private,
            public,
            public_header: encode_u128(public),
        })
    }

    pub fn public_header(&self) -> String {
        self.public_header.clone()
    }

    pub fn create_sender_session(
        &self,
        receiver_public_header: &str,
    ) -> Result<SenderSession, String> {
        let receiver_public = decode_u128(receiver_public_header)?;
        let private = random_private()?;
        let sender_public = dh_public(private);
        let shared = dh_shared(receiver_public, private);
        let nonce = random_nonce()?;
        let crypto = derive_transfer_crypto(shared, sender_public, receiver_public, nonce);

        Ok(SenderSession {
            sender_public_header: encode_u128(sender_public),
            nonce_header: encode_bytes(&nonce),
            crypto,
        })
    }

    pub fn create_receiver_session(
        &self,
        sender_public_header: &str,
        nonce_header: &str,
    ) -> Result<TransferCrypto, String> {
        let sender_public = decode_u128(sender_public_header)?;
        let nonce = decode_nonce(nonce_header)?;
        let shared = dh_shared(sender_public, self.private);
        Ok(derive_transfer_crypto(
            shared,
            sender_public,
            self.public,
            nonce,
        ))
    }
}

impl TransferCrypto {
    pub fn stream_cipher(&self) -> StreamCipher {
        StreamCipher {
            key: self.cipher_key,
            nonce: self.nonce,
            counter: 0,
            block: [0; 64],
            block_index: 64,
        }
    }

    pub fn hmac(&self) -> HmacSha256 {
        HmacSha256::new(&self.mac_key)
    }
}

impl StreamCipher {
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.block_index >= self.block.len() {
                self.refill();
            }
            *byte ^= self.block[self.block_index];
            self.block_index += 1;
        }
    }

    fn refill(&mut self) {
        self.block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.counter = self.counter.wrapping_add(1);
        self.block_index = 0;
    }
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 16]) -> [u8; 64] {
    let constants = *b"expand 32-byte k";
    let mut state = [0_u32; 16];
    state[0] = u32::from_le_bytes(constants[0..4].try_into().unwrap());
    state[1] = u32::from_le_bytes(constants[4..8].try_into().unwrap());
    state[2] = u32::from_le_bytes(constants[8..12].try_into().unwrap());
    state[3] = u32::from_le_bytes(constants[12..16].try_into().unwrap());

    for index in 0..8 {
        let start = index * 4;
        state[4 + index] = u32::from_le_bytes(key[start..start + 4].try_into().unwrap());
    }

    state[12] = counter;
    state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    for index in 0..16 {
        working[index] = working[index].wrapping_add(state[index]);
    }

    let mut output = [0_u8; 64];
    for (index, word) in working.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    output
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut normalized = [0_u8; 64];
        if key.len() > normalized.len() {
            normalized[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            normalized[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0x36_u8; 64];
        let mut outer_key = [0x5c_u8; 64];
        for index in 0..64 {
            inner_key[index] ^= normalized[index];
            outer_key[index] ^= normalized[index];
        }

        let mut inner = Sha256::new();
        inner.update(inner_key);
        Self { inner, outer_key }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer_key);
        outer.update(inner);
        outer.finalize().into()
    }
}

pub fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_mac(value: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| format!("加密校验值无效：{error}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "加密校验值长度无效".to_string())
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn derive_transfer_crypto(
    shared: u128,
    sender_public: u128,
    receiver_public: u128,
    nonce: [u8; 16],
) -> TransferCrypto {
    let mut transfer = Sha256::new();
    transfer.update(TRANSFER_CONTEXT);
    transfer.update(shared.to_be_bytes());
    transfer.update(sender_public.to_be_bytes());
    transfer.update(receiver_public.to_be_bytes());
    let transfer_key: [u8; 32] = transfer.finalize().into();

    let mut cipher = Sha256::new();
    cipher.update(CIPHER_CONTEXT);
    cipher.update(transfer_key);
    let cipher_key = cipher.finalize().into();

    let mut mac = Sha256::new();
    mac.update(MAC_CONTEXT);
    mac.update(transfer_key);
    let mac_key = mac.finalize().into();

    TransferCrypto {
        cipher_key,
        mac_key,
        nonce,
    }
}

fn random_private() -> Result<u128, String> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes)?;
    bytes[0] &= 0x7f;
    Ok((u128::from_be_bytes(bytes) % (DH_PRIME - 3)) + 2)
}

fn random_nonce() -> Result<[u8; 16], String> {
    let mut nonce = [0_u8; 16];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

#[cfg(unix)]
fn fill_random(bytes: &mut [u8]) -> Result<(), String> {
    use std::{fs::File, io::Read};

    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(bytes))
        .map_err(|error| format!("生成加密随机数失败：{error}"))
}

#[cfg(windows)]
fn fill_random(bytes: &mut [u8]) -> Result<(), String> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }

    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("生成加密随机数失败：BCryptGenRandom {status}"))
    }
}

fn dh_public(private: u128) -> u128 {
    mod_pow(DH_GENERATOR, private)
}

fn dh_shared(public: u128, private: u128) -> u128 {
    mod_pow(public, private)
}

fn mod_pow(mut base: u128, mut exponent: u128) -> u128 {
    let mut result = 1_u128;
    base %= DH_PRIME;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
        exponent >>= 1;
    }

    result
}

fn mod_mul(mut left: u128, mut right: u128) -> u128 {
    let mut result = 0_u128;
    while right > 0 {
        if right & 1 == 1 {
            result = mod_add(result, left);
        }
        left = mod_add(left, left);
        right >>= 1;
    }
    result
}

fn mod_add(left: u128, right: u128) -> u128 {
    let sum = left + right;
    if sum >= DH_PRIME {
        sum - DH_PRIME
    } else {
        sum
    }
}

fn encode_u128(value: u128) -> String {
    encode_bytes(&value.to_be_bytes())
}

fn decode_u128(value: &str) -> Result<u128, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| format!("设备加密公钥无效：{error}"))?;
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "设备加密公钥长度无效".to_string())?;
    let value = u128::from_be_bytes(bytes);
    if !(2..DH_PRIME).contains(&value) {
        return Err("设备加密公钥范围无效".to_string());
    }
    Ok(value)
}

fn decode_nonce(value: &str) -> Result<[u8; 16], String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|error| format!("加密 nonce 无效：{error}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "加密 nonce 长度无效".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_same_transfer_key_on_both_sides() {
        let receiver = KeyPair::generate().unwrap();
        let sender = KeyPair::generate().unwrap();
        let sender_session = sender
            .create_sender_session(&receiver.public_header())
            .unwrap();
        let receiver_session = receiver
            .create_receiver_session(
                &sender_session.sender_public_header,
                &sender_session.nonce_header,
            )
            .unwrap();

        let mut encrypted = b"hello encrypted lan".to_vec();
        let mut sender_cipher = sender_session.crypto.stream_cipher();
        sender_cipher.apply(&mut encrypted);

        let mut decrypted = encrypted.clone();
        let mut receiver_cipher = receiver_session.stream_cipher();
        receiver_cipher.apply(&mut decrypted);

        assert_eq!(decrypted, b"hello encrypted lan");
    }

    #[test]
    fn hmac_detects_different_content() {
        let crypto = KeyPair::generate()
            .unwrap()
            .create_sender_session(&KeyPair::generate().unwrap().public_header())
            .unwrap()
            .crypto;
        let mut left = crypto.hmac();
        left.update(b"left");
        let mut right = crypto.hmac();
        right.update(b"right");
        assert!(!constant_time_eq(&left.finalize(), &right.finalize()));
    }
}
