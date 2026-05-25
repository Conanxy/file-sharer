use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    env,
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::Emitter;

use crate::{
    crypto::{self, KeyPair},
    publish_received_file,
};

const PROTOCOL: &str = "file-sharer.v2";
const DISCOVERY_PORT: u16 = 45891;
const TRANSFER_PORT: u16 = 45892;
const DEVICE_TTL_MS: u128 = 12_000;
const BEACON_INTERVAL: Duration = Duration::from_secs(2);
const MAX_TRANSFER_HISTORY: usize = 100;
const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;
const TRANSFER_PROGRESS_EVENT: &str = "transfer-progress";

#[derive(Clone)]
pub struct NetworkService {
    identity: Arc<Mutex<Identity>>,
    key_pair: Arc<KeyPair>,
    state: Arc<Mutex<NetworkState>>,
    receive_dir: Arc<Mutex<Option<PathBuf>>>,
    history: Arc<Mutex<Vec<TransferEvent>>>,
    app: Arc<Mutex<Option<tauri::AppHandle>>>,
    cancelled_transfers: Arc<Mutex<HashSet<String>>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub port: u16,
    pub crypto_public_key: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub address: String,
    pub port: u16,
    pub last_seen_ms: u128,
    pub crypto_public_key: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferReceipt {
    pub file_name: String,
    pub target_name: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferEvent {
    pub direction: TransferDirection,
    pub file_name: String,
    pub peer_name: String,
    pub bytes: u64,
    pub saved_path: Option<String>,
    pub timestamp_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub direction: TransferDirection,
    pub phase: TransferPhase,
    pub file_name: String,
    pub peer_name: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub encrypted: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Sent,
    Received,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferPhase {
    Started,
    Progress,
    Finished,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Beacon {
    protocol: String,
    id: String,
    name: String,
    platform: String,
    port: u16,
    crypto_public_key: String,
}

#[derive(Default)]
struct NetworkState {
    devices: HashMap<String, DeviceInfo>,
}

impl NetworkService {
    pub fn new() -> Arc<Self> {
        let name = device_name();
        let platform = env::consts::OS.to_string();
        let id = stable_device_id(&name, &platform);
        let key_pair = Arc::new(KeyPair::generate().expect("failed to initialize encryption keys"));
        let identity = Identity {
            id,
            name,
            platform,
            port: TRANSFER_PORT,
            crypto_public_key: key_pair.public_header(),
        };

        Arc::new(Self {
            identity: Arc::new(Mutex::new(identity)),
            key_pair,
            state: Arc::new(Mutex::new(NetworkState::default())),
            receive_dir: Arc::new(Mutex::new(None)),
            history: Arc::new(Mutex::new(Vec::new())),
            app: Arc::new(Mutex::new(None)),
            cancelled_transfers: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn set_receive_dir(&self, receive_dir: PathBuf) {
        let mut configured_dir = self.receive_dir.lock().expect("receive dir poisoned");
        *configured_dir = Some(receive_dir);
    }

    pub fn set_app_handle(&self, app: tauri::AppHandle) {
        let mut configured_app = self.app.lock().expect("app handle poisoned");
        *configured_app = Some(app);
    }

    pub fn start(self: &Arc<Self>) {
        self.start_discovery_listener();
        self.start_beacon_loop();
        self.start_transfer_listener();
    }

    pub fn identity(&self) -> Identity {
        self.identity.lock().expect("identity poisoned").clone()
    }

    pub fn set_device_name(&self, name: String) -> Result<Identity, String> {
        let name = sanitize_device_name(&name);
        if name.is_empty() {
            return Err("设备名称不能为空".to_string());
        }

        let mut identity = self
            .identity
            .lock()
            .map_err(|_| "设备身份状态异常".to_string())?;
        identity.name = name;
        Ok(identity.clone())
    }

    pub fn devices(&self) -> Vec<DeviceInfo> {
        let now = now_ms();
        let mut state = self.state.lock().expect("network state poisoned");
        state
            .devices
            .retain(|_, device| now.saturating_sub(device.last_seen_ms) <= DEVICE_TTL_MS);

        let mut devices = state.devices.values().cloned().collect::<Vec<_>>();
        devices.sort_by(|left, right| left.name.cmp(&right.name));
        devices
    }

    pub fn transfer_history(&self) -> Vec<TransferEvent> {
        self.history
            .lock()
            .expect("transfer history poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub fn clear_transfer_history(&self) {
        self.history
            .lock()
            .expect("transfer history poisoned")
            .clear();
    }

    pub fn record_sent_transfer(&self, file_name: String, peer_name: String, bytes: u64) {
        self.push_history(TransferEvent {
            direction: TransferDirection::Sent,
            file_name,
            peer_name,
            bytes,
            saved_path: None,
            timestamp_ms: now_ms(),
        });
    }

    pub fn cancel_transfer(&self, transfer_id: String) {
        if let Ok(mut cancelled_transfers) = self.cancelled_transfers.lock() {
            cancelled_transfers.insert(transfer_id);
        }
    }

    pub fn send_files(
        &self,
        paths: Vec<String>,
        target_id: Option<String>,
    ) -> Result<Vec<TransferReceipt>, String> {
        if paths.is_empty() {
            return Err("没有可发送的文件".to_string());
        }

        let target_id = target_id.ok_or_else(|| "缺少目标设备".to_string())?;
        let target = self
            .devices()
            .into_iter()
            .find(|device| device.id == target_id)
            .ok_or_else(|| "目标设备不在线".to_string())?;

        let target_addr = target
            .address
            .parse::<IpAddr>()
            .map_err(|error| format!("目标地址无效：{error}"))?;

        if !is_lan_ip(&target_addr) {
            return Err("目标设备不在局域网地址范围内".to_string());
        }

        let mut receipts = Vec::new();
        for path in paths {
            let receipt = self.send_file(Path::new(&path), &target)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn send_file(&self, path: &Path, target: &DeviceInfo) -> Result<TransferReceipt, String> {
        let metadata = fs::metadata(path).map_err(|error| format!("读取文件失败：{error}"))?;
        if !metadata.is_file() {
            return Err(format!("只支持发送文件：{}", path.display()));
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "文件名无效".to_string())?
            .to_string();
        let transfer_file_name = sanitize_file_name(&file_name);

        let mut file = File::open(path).map_err(|error| format!("打开文件失败：{error}"))?;
        let address = format!("{}:{}", target.address, target.port);
        let socket_addr = address
            .parse::<SocketAddr>()
            .map_err(|error| format!("目标地址无效：{error}"))?;
        let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))
            .map_err(|error| format!("连接目标失败：{error}"))?;

        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|error| format!("设置发送超时失败：{error}"))?;

        let identity = self.identity();
        let session = self
            .key_pair
            .create_sender_session(&target.crypto_public_key)
            .map_err(|error| format!("创建加密会话失败：{error}"))?;
        let transfer_id = transfer_id(&identity.id, &target.id, &file_name);

        self.emit_progress(TransferProgress {
            transfer_id: transfer_id.clone(),
            direction: TransferDirection::Sent,
            phase: TransferPhase::Started,
            file_name: file_name.clone(),
            peer_name: target.name.clone(),
            bytes_transferred: 0,
            total_bytes: metadata.len(),
            encrypted: true,
            error: None,
        });

        let plaintext_mac = match self.file_mac(
            path,
            &session.crypto,
            &transfer_file_name,
            &identity.name,
            &transfer_id,
            metadata.len(),
            None,
        ) {
            Ok(mac) => mac,
            Err(error) => {
                let error = format!("计算加密校验失败：{error}");
                self.emit_progress(TransferProgress {
                    transfer_id,
                    direction: TransferDirection::Sent,
                    phase: TransferPhase::Failed,
                    file_name,
                    peer_name: target.name.clone(),
                    bytes_transferred: 0,
                    total_bytes: metadata.len(),
                    encrypted: true,
                    error: Some(error.clone()),
                });
                return Err(error);
            }
        };
        let header = format!(
            "POST /upload HTTP/1.1\r\n\
             Host: {address}\r\n\
             Content-Length: {}\r\n\
             X-File-Sharer-Protocol: {PROTOCOL}\r\n\
             X-Sender-Id: {}\r\n\
            X-Sender-Name: {}\r\n\
             X-File-Name: {}\r\n\
             X-Transfer-Id: {}\r\n\
             X-Crypto-Mode: {}\r\n\
             X-Crypto-Sender-Public: {}\r\n\
             X-Crypto-Nonce: {}\r\n\
             X-Crypto-Mac: {}\r\n\
            Connection: close\r\n\r\n",
            metadata.len(),
            identity.id,
            percent_encode(&identity.name),
            percent_encode(&transfer_file_name),
            percent_encode(&transfer_id),
            crypto::CRYPTO_MODE,
            session.sender_public_header,
            session.nonce_header,
            plaintext_mac,
        );
        stream
            .write_all(header.as_bytes())
            .map_err(|error| format!("写入请求头失败：{error}"))?;

        let mut cipher = session.crypto.stream_cipher();
        let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];
        let mut sent_bytes = 0_u64;

        loop {
            self.ensure_not_cancelled(&transfer_id).map_err(|error| {
                self.emit_progress(TransferProgress {
                    transfer_id: transfer_id.clone(),
                    direction: TransferDirection::Sent,
                    phase: TransferPhase::Failed,
                    file_name: file_name.clone(),
                    peer_name: target.name.clone(),
                    bytes_transferred: sent_bytes,
                    total_bytes: metadata.len(),
                    encrypted: true,
                    error: Some(error.clone()),
                });
                error
            })?;
            let bytes_read = file
                .read(&mut buffer)
                .map_err(|error| format!("读取文件失败：{error}"))?;
            if bytes_read == 0 {
                break;
            }

            let chunk = &mut buffer[..bytes_read];
            cipher.apply(chunk);
            stream
                .write_all(chunk)
                .map_err(|error| format!("发送文件失败：{error}"))?;
            sent_bytes += bytes_read as u64;
            self.emit_progress(TransferProgress {
                transfer_id: transfer_id.clone(),
                direction: TransferDirection::Sent,
                phase: TransferPhase::Progress,
                file_name: file_name.clone(),
                peer_name: target.name.clone(),
                bytes_transferred: sent_bytes,
                total_bytes: metadata.len(),
                encrypted: true,
                error: None,
            });
        }

        let mut response = String::new();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = BufReader::new(stream).read_to_string(&mut response);
        if !response.starts_with("HTTP/1.1 200") {
            let error = format!(
                "接收端拒绝：{}",
                response.lines().next().unwrap_or("无响应")
            );
            self.emit_progress(TransferProgress {
                transfer_id,
                direction: TransferDirection::Sent,
                phase: TransferPhase::Failed,
                file_name,
                peer_name: target.name.clone(),
                bytes_transferred: sent_bytes,
                total_bytes: metadata.len(),
                encrypted: true,
                error: Some(error.clone()),
            });
            return Err(error);
        }

        self.push_history(TransferEvent {
            direction: TransferDirection::Sent,
            file_name: file_name.clone(),
            peer_name: target.name.clone(),
            bytes: metadata.len(),
            saved_path: None,
            timestamp_ms: now_ms(),
        });

        self.emit_progress(TransferProgress {
            transfer_id,
            direction: TransferDirection::Sent,
            phase: TransferPhase::Finished,
            file_name: file_name.clone(),
            peer_name: target.name.clone(),
            bytes_transferred: metadata.len(),
            total_bytes: metadata.len(),
            encrypted: true,
            error: None,
        });

        Ok(TransferReceipt {
            file_name,
            target_name: target.name.clone(),
            bytes: metadata.len(),
        })
    }

    fn file_mac(
        &self,
        path: &Path,
        crypto: &crypto::TransferCrypto,
        file_name: &str,
        peer_name: &str,
        transfer_id: &str,
        total_bytes: u64,
        progress_peer: Option<(String, TransferDirection)>,
    ) -> Result<String, String> {
        let mut file = File::open(path).map_err(|error| error.to_string())?;
        let mut hmac = crypto.hmac();
        hmac.update(PROTOCOL.as_bytes());
        hmac.update(transfer_id.as_bytes());
        hmac.update(file_name.as_bytes());
        hmac.update(peer_name.as_bytes());
        hmac.update(&total_bytes.to_be_bytes());

        let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];
        let mut scanned_bytes = 0_u64;
        loop {
            self.ensure_not_cancelled(transfer_id)?;
            let bytes_read = file.read(&mut buffer).map_err(|error| error.to_string())?;
            if bytes_read == 0 {
                break;
            }
            hmac.update(&buffer[..bytes_read]);
            scanned_bytes += bytes_read as u64;
            if let Some((peer_name, direction)) = &progress_peer {
                self.emit_progress(TransferProgress {
                    transfer_id: transfer_id.to_string(),
                    direction: direction.clone(),
                    phase: TransferPhase::Progress,
                    file_name: file_name.to_string(),
                    peer_name: peer_name.clone(),
                    bytes_transferred: scanned_bytes,
                    total_bytes,
                    encrypted: true,
                    error: None,
                });
            }
        }

        Ok(crypto::encode_bytes(&hmac.finalize()))
    }

    fn start_discovery_listener(self: &Arc<Self>) {
        let service = self.clone();
        thread::spawn(move || {
            let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)) {
                Ok(socket) => socket,
                Err(error) => {
                    eprintln!("discovery bind failed: {error}");
                    return;
                }
            };
            if let Err(error) = socket.set_broadcast(true) {
                eprintln!("enable discovery broadcast failed: {error}");
            }
            let mut buffer = [0_u8; 2048];

            loop {
                let Ok((size, source)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                if !is_lan_ip(&source.ip()) {
                    continue;
                }

                let Ok(beacon) = serde_json::from_slice::<Beacon>(&buffer[..size]) else {
                    continue;
                };

                if beacon.protocol != PROTOCOL || beacon.id == service.identity().id {
                    continue;
                }

                if let Ok(payload) = serde_json::to_vec(&service.beacon()) {
                    let reply_to = SocketAddr::new(source.ip(), DISCOVERY_PORT);
                    let _ = socket.send_to(&payload, reply_to);
                }

                let mut state = service.state.lock().expect("network state poisoned");
                state.devices.insert(
                    beacon.id.clone(),
                    DeviceInfo {
                        id: beacon.id,
                        name: beacon.name,
                        platform: beacon.platform,
                        address: source.ip().to_string(),
                        port: beacon.port,
                        last_seen_ms: now_ms(),
                        crypto_public_key: beacon.crypto_public_key,
                    },
                );
            }
        });
    }

    fn start_beacon_loop(self: &Arc<Self>) {
        let service = self.clone();
        thread::spawn(move || {
            let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                Ok(socket) => socket,
                Err(error) => {
                    eprintln!("beacon bind failed: {error}");
                    return;
                }
            };
            if let Err(error) = socket.set_broadcast(true) {
                eprintln!("enable broadcast failed: {error}");
                return;
            }

            loop {
                if let Ok(payload) = serde_json::to_vec(&service.beacon()) {
                    let _ = socket.send_to(
                        &payload,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT),
                    );
                }
                thread::sleep(BEACON_INTERVAL);
            }
        });
    }

    fn beacon(&self) -> Beacon {
        let identity = self.identity();
        Beacon {
            protocol: PROTOCOL.to_string(),
            id: identity.id,
            name: identity.name,
            platform: identity.platform,
            port: identity.port,
            crypto_public_key: identity.crypto_public_key,
        }
    }

    fn start_transfer_listener(self: &Arc<Self>) {
        let service = self.clone();
        thread::spawn(move || {
            let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, TRANSFER_PORT)) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("transfer bind failed: {error}");
                    return;
                }
            };

            for incoming in listener.incoming() {
                let Ok(stream) = incoming else {
                    continue;
                };
                if let Ok(peer) = stream.peer_addr() {
                    if !is_lan_ip(&peer.ip()) {
                        continue;
                    }
                }
                let service = service.clone();
                thread::spawn(move || {
                    if let Err(error) = service.handle_upload(stream) {
                        eprintln!("upload failed: {error}");
                    }
                });
            }
        });
    }

    fn handle_upload(&self, stream: TcpStream) -> io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let request_line = request_line.trim_end().to_string();

        let headers = read_headers(&mut reader)?;
        if request_line.starts_with("OPTIONS ") {
            return write_response(reader.into_inner(), 204, "No Content", "{}");
        }

        if !request_line.starts_with("POST /upload ") {
            return write_response(reader.into_inner(), 404, "Not Found", "{}");
        }

        let protocol = header_value(&headers, "x-file-sharer-protocol").unwrap_or_default();
        if protocol != PROTOCOL {
            return write_response(reader.into_inner(), 400, "Bad Request", "{}");
        }

        let crypto_mode = header_value(&headers, "x-crypto-mode").unwrap_or_default();
        if crypto_mode != crypto::CRYPTO_MODE {
            return write_response(reader.into_inner(), 400, "Bad Request", "{}");
        }

        let file_name = header_value(&headers, "x-file-name")
            .and_then(|value| percent_decode(&value).ok())
            .map(|value| sanitize_file_name(&value))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "shared-file".to_string());
        let sender_name = header_value(&headers, "x-sender-name")
            .and_then(|value| percent_decode(&value).ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "Unknown device".to_string());
        let content_length = header_value(&headers, "content-length")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing content-length"))?;
        let transfer_id = header_value(&headers, "x-transfer-id")
            .and_then(|value| percent_decode(&value).ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| transfer_id("remote", &self.identity().id, &file_name));
        let sender_public = match header_value(&headers, "x-crypto-sender-public") {
            Some(value) => value,
            None => return write_response(reader.into_inner(), 400, "Bad Request", "{}"),
        };
        let nonce = match header_value(&headers, "x-crypto-nonce") {
            Some(value) => value,
            None => return write_response(reader.into_inner(), 400, "Bad Request", "{}"),
        };
        let expected_mac = match header_value(&headers, "x-crypto-mac")
            .and_then(|value| crypto::decode_mac(&value).ok())
        {
            Some(value) => value,
            None => return write_response(reader.into_inner(), 400, "Bad Request", "{}"),
        };
        let transfer_crypto = match self
            .key_pair
            .create_receiver_session(&sender_public, &nonce)
        {
            Ok(transfer_crypto) => transfer_crypto,
            Err(error) => {
                let body = format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&error));
                return write_response(reader.into_inner(), 400, "Bad Request", &body);
            }
        };

        let destination = match unique_destination(&self.receive_directory(), &file_name) {
            Ok(destination) => destination,
            Err(error) => {
                let body = format!(
                    "{{\"ok\":false,\"error\":\"{}\"}}",
                    json_escape(&error.to_string())
                );
                return write_response(reader.into_inner(), 500, "Internal Server Error", &body);
            }
        };

        self.emit_progress(TransferProgress {
            transfer_id: transfer_id.clone(),
            direction: TransferDirection::Received,
            phase: TransferPhase::Started,
            file_name: file_name.clone(),
            peer_name: sender_name.clone(),
            bytes_transferred: 0,
            total_bytes: content_length,
            encrypted: true,
            error: None,
        });

        let mut output = match File::create(&destination) {
            Ok(output) => output,
            Err(error) => {
                let body = format!(
                    "{{\"ok\":false,\"error\":\"{}\"}}",
                    json_escape(&error.to_string())
                );
                return write_response(reader.into_inner(), 500, "Internal Server Error", &body);
            }
        };
        let mut cipher = transfer_crypto.stream_cipher();
        let mut hmac = transfer_crypto.hmac();
        hmac.update(PROTOCOL.as_bytes());
        hmac.update(transfer_id.as_bytes());
        hmac.update(file_name.as_bytes());
        hmac.update(sender_name.as_bytes());
        hmac.update(&content_length.to_be_bytes());

        let mut remaining = content_length;
        let mut received = 0_u64;
        let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];

        while remaining > 0 {
            if self.is_cancelled(&transfer_id) {
                let _ = fs::remove_file(&destination);
                self.emit_progress(TransferProgress {
                    transfer_id,
                    direction: TransferDirection::Received,
                    phase: TransferPhase::Failed,
                    file_name: file_name.clone(),
                    peer_name: sender_name,
                    bytes_transferred: received,
                    total_bytes: content_length,
                    encrypted: true,
                    error: Some("传输已取消".to_string()),
                });
                return write_response(
                    reader.into_inner(),
                    499,
                    "Client Closed Request",
                    "{\"ok\":false,\"error\":\"cancelled\"}",
                );
            }
            let read_size = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..read_size])?;
            let chunk = &mut buffer[..read_size];
            cipher.apply(chunk);
            hmac.update(chunk);
            if let Err(error) = output.write_all(chunk) {
                let body = format!(
                    "{{\"ok\":false,\"error\":\"{}\"}}",
                    json_escape(&error.to_string())
                );
                return write_response(reader.into_inner(), 500, "Internal Server Error", &body);
            }
            remaining -= read_size as u64;
            received += read_size as u64;
            self.emit_progress(TransferProgress {
                transfer_id: transfer_id.clone(),
                direction: TransferDirection::Received,
                phase: TransferPhase::Progress,
                file_name: file_name.clone(),
                peer_name: sender_name.clone(),
                bytes_transferred: received,
                total_bytes: content_length,
                encrypted: true,
                error: None,
            });
        }

        if let Err(error) = output.flush() {
            let body = format!(
                "{{\"ok\":false,\"error\":\"{}\"}}",
                json_escape(&error.to_string())
            );
            return write_response(reader.into_inner(), 500, "Internal Server Error", &body);
        }

        let actual_mac = hmac.finalize();
        if !crypto::constant_time_eq(&actual_mac, &expected_mac) {
            let _ = fs::remove_file(&destination);
            self.emit_progress(TransferProgress {
                transfer_id,
                direction: TransferDirection::Received,
                phase: TransferPhase::Failed,
                file_name: file_name.clone(),
                peer_name: sender_name,
                bytes_transferred: received,
                total_bytes: content_length,
                encrypted: true,
                error: Some("加密校验失败".to_string()),
            });
            return write_response(
                reader.into_inner(),
                400,
                "Bad Request",
                "{\"ok\":false,\"error\":\"crypto verification failed\"}",
            );
        }

        let saved_path = publish_received_file(&self.app_handle(), &destination)
            .map(|published| published.uri)
            .unwrap_or_else(|| destination.display().to_string());

        self.push_history(TransferEvent {
            direction: TransferDirection::Received,
            file_name: file_name.clone(),
            peer_name: sender_name.clone(),
            bytes: content_length,
            saved_path: Some(saved_path),
            timestamp_ms: now_ms(),
        });

        self.emit_progress(TransferProgress {
            transfer_id,
            direction: TransferDirection::Received,
            phase: TransferPhase::Finished,
            file_name: file_name.clone(),
            peer_name: sender_name,
            bytes_transferred: content_length,
            total_bytes: content_length,
            encrypted: true,
            error: None,
        });

        let response_body = format!(
            "{{\"ok\":true,\"file\":\"{}\"}}",
            json_escape(&destination.display().to_string())
        );
        write_response(reader.into_inner(), 200, "OK", &response_body)
    }

    fn receive_directory(&self) -> PathBuf {
        self.receive_dir
            .lock()
            .expect("receive dir poisoned")
            .clone()
            .unwrap_or_else(default_receive_dir)
    }

    fn app_handle(&self) -> Option<tauri::AppHandle> {
        self.app.lock().expect("app handle poisoned").clone()
    }

    fn push_history(&self, event: TransferEvent) {
        let mut history = self.history.lock().expect("transfer history poisoned");
        history.push(event);
        if history.len() > MAX_TRANSFER_HISTORY {
            let overflow = history.len() - MAX_TRANSFER_HISTORY;
            history.drain(0..overflow);
        }
    }

    fn emit_progress(&self, progress: TransferProgress) {
        let app = self.app.lock().expect("app handle poisoned").clone();
        if let Some(app) = app {
            let _ = app.emit(TRANSFER_PROGRESS_EVENT, progress);
        }
    }

    fn is_cancelled(&self, transfer_id: &str) -> bool {
        self.cancelled_transfers
            .lock()
            .map(|cancelled_transfers| cancelled_transfers.contains(transfer_id))
            .unwrap_or(false)
    }

    fn ensure_not_cancelled(&self, transfer_id: &str) -> Result<(), String> {
        if self.is_cancelled(transfer_id) {
            Err("传输已取消".to_string())
        } else {
            Ok(())
        }
    }
}

fn read_headers(reader: &mut BufReader<TcpStream>) -> io::Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok(headers)
}

fn header_value(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get(name).cloned()
}

fn write_response(mut stream: TcpStream, status: u16, text: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {text}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, X-File-Sharer-Protocol, X-Sender-Id, X-Sender-Name, X-File-Name, X-Transfer-Id, X-Crypto-Mode, X-Crypto-Sender-Public, X-Crypto-Nonce, X-Crypto-Mac\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.as_bytes().len()
    );
    stream.write_all(response.as_bytes())
}

fn is_lan_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_lan_ipv4(ip),
        IpAddr::V6(ip) => is_lan_ipv6(ip),
    }
}

fn is_lan_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

fn is_lan_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unicast_link_local() || is_unique_local_ipv6(ip)
}

fn is_unique_local_ipv6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn unique_destination(directory: &Path, file_name: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(&directory)?;

    let mut destination = directory.join(file_name);
    if !destination.exists() {
        return Ok(destination);
    }

    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = path.extension().and_then(|value| value.to_str());

    for index in 1..10_000 {
        let candidate_name = match extension {
            Some(extension) if !extension.is_empty() => format!("{stem} ({index}).{extension}"),
            _ => format!("{stem} ({index})"),
        };
        destination = directory.join(candidate_name);
        if !destination.exists() {
            return Ok(destination);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many duplicate file names",
    ))
}

fn default_receive_dir() -> PathBuf {
    if let Some(home) = home_dir() {
        let downloads = home.join("Downloads");
        if downloads.exists() {
            return downloads.join("File Sharer");
        }
    }

    env::current_dir()
        .unwrap_or_else(|_| env::temp_dir())
        .join("received")
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
}

fn device_name() -> String {
    sanitize_device_name(
        &env::var("COMPUTERNAME")
            .or_else(|_| env::var("HOSTNAME"))
            .or_else(|_| env::var("USER"))
            .or_else(|_| env::var("USERNAME"))
            .map(|name| format!("{name}'s {}", env::consts::OS))
            .unwrap_or_else(|_| format!("File Sharer {}", env::consts::OS)),
    )
}

fn stable_device_id(name: &str, platform: &str) -> String {
    let user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    platform.hash(&mut hasher);
    user.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn transfer_id(sender_id: &str, target_id: &str, file_name: &str) -> String {
    let mut hasher = DefaultHasher::new();
    sender_id.hash(&mut hasher);
    target_id.hash(&mut hasher);
    file_name.hash(&mut hasher);
    now_ms().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn sanitize_file_name(file_name: &str) -> String {
    file_name
        .chars()
        .map(|character| match character {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => '_',
            character if character.is_control() => '_',
            character => character,
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string()
}

fn sanitize_device_name(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(32)
        .collect::<String>()
        .trim()
        .to_string()
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("invalid percent encoding".to_string());
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| "invalid percent encoding".to_string())?;
            let byte =
                u8::from_str_radix(hex, 16).map_err(|_| "invalid percent encoding".to_string())?;
            output.push(byte);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).map_err(|_| "invalid utf-8".to_string())
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_round_trips_utf8_names() {
        let name = "季度 报告 01.txt";
        let encoded = percent_encode(name);
        assert_eq!(percent_decode(&encoded).unwrap(), name);
    }

    #[test]
    fn sanitizes_path_like_file_names() {
        assert_eq!(
            sanitize_file_name("../secret:file?.txt"),
            "_secret_file_.txt"
        );
    }

    #[test]
    fn accepts_only_lan_scoped_addresses() {
        assert!(is_lan_ip(&"192.168.1.12".parse().unwrap()));
        assert!(is_lan_ip(&"10.0.0.8".parse().unwrap()));
        assert!(is_lan_ip(&"172.16.4.2".parse().unwrap()));
        assert!(is_lan_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_lan_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn sends_file_to_local_receiver() {
        let sender = NetworkService::new();
        let receiver = NetworkService::new();
        let receive_dir = env::temp_dir().join(format!("file-sharer-test-{}", now_ms()));
        receiver.set_receive_dir(receive_dir.clone());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let receiver_for_thread = receiver.clone();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            receiver_for_thread.handle_upload(stream).unwrap();
        });
        std::thread::sleep(Duration::from_millis(120));

        let source_path = receive_dir.with_file_name("甘**-开发.docx");
        fs::write(&source_path, "hello from mac sender").unwrap();
        let receiver_identity = receiver.identity();
        let receipt = sender
            .send_file(
                &source_path,
                &DeviceInfo {
                    id: receiver_identity.id,
                    name: "local receiver".to_string(),
                    platform: "test".to_string(),
                    address: "127.0.0.1".to_string(),
                    port,
                    last_seen_ms: now_ms(),
                    crypto_public_key: receiver_identity.crypto_public_key,
                },
            )
            .unwrap();
        handle.join().unwrap();

        assert_eq!(
            receipt.file_name,
            source_path.file_name().unwrap().to_string_lossy()
        );
        let received_path = receive_dir.join(sanitize_file_name(
            &source_path.file_name().unwrap().to_string_lossy(),
        ));
        assert_eq!(
            fs::read_to_string(received_path).unwrap(),
            "hello from mac sender"
        );

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_dir_all(receive_dir);
    }
}
