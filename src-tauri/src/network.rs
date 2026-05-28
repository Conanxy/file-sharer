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
use socket2::{Domain, Protocol, Socket, Type};
use tauri::{Emitter, Manager};

use crate::{
    crypto::{self, KeyPair},
    publish_received_file,
};

const PROTOCOL: &str = "file-sharer.v2";
const GOODBYE_PROTOCOL: &str = "file-sharer.v2.goodbye";
const PROBE_PROTOCOL: &str = "file-sharer.v2.probe";
const DISCOVERY_PORT: u16 = 45891;
const TRANSFER_PORT: u16 = 45892;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 99);
const DEVICE_TTL_MS: u128 = 6_000;
const BEACON_INTERVAL_FAST: Duration = Duration::from_millis(500);
const BEACON_INTERVAL_SLOW: Duration = Duration::from_secs(5);
const BEACON_BACKOFF_THRESHOLD_MS: u128 = 30_000;
const MAX_TRANSFER_HISTORY: usize = 100;
const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;
const TRANSFER_PROGRESS_EVENT: &str = "transfer-progress";
const DEVICE_DISCOVERED_EVENT: &str = "device-discovered";
const DEVICE_LOST_EVENT: &str = "device-lost";
const DISCOVERY_BURST_COUNT: usize = 5;
const DISCOVERY_BURST_INTERVAL: Duration = Duration::from_millis(60);

#[derive(Clone)]
pub struct NetworkService {
    identity: Arc<Mutex<Identity>>,
    key_pair: Arc<KeyPair>,
    state: Arc<Mutex<NetworkState>>,
    receive_dir: Arc<Mutex<Option<PathBuf>>>,
    history: Arc<Mutex<Vec<TransferEvent>>>,
    history_path: Arc<Mutex<Option<PathBuf>>>,
    app: Arc<Mutex<Option<tauri::AppHandle>>>,
    cancelled_transfers: Arc<Mutex<HashSet<String>>>,
    progress_timestamps: Arc<Mutex<HashMap<String, (u128, u64)>>>,
    discovery_enabled: Arc<Mutex<bool>>,
    last_new_device_ms: Arc<Mutex<u128>>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub speed_mbps: f64,
    pub eta_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Sent,
    Received,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Goodbye {
    protocol: String,
    id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Probe {
    protocol: String,
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

        let now = now_ms();
        Arc::new(Self {
            identity: Arc::new(Mutex::new(identity)),
            key_pair,
            state: Arc::new(Mutex::new(NetworkState::default())),
            receive_dir: Arc::new(Mutex::new(None)),
            history: Arc::new(Mutex::new(Vec::new())),
            history_path: Arc::new(Mutex::new(None)),
            app: Arc::new(Mutex::new(None)),
            cancelled_transfers: Arc::new(Mutex::new(HashSet::new())),
            progress_timestamps: Arc::new(Mutex::new(HashMap::new())),
            discovery_enabled: Arc::new(Mutex::new(true)),
            last_new_device_ms: Arc::new(Mutex::new(now)),
        })
    }

    pub fn set_receive_dir(&self, receive_dir: PathBuf) {
        let mut configured_dir = self.receive_dir.lock().expect("receive dir poisoned");
        *configured_dir = Some(receive_dir);
    }

    pub fn set_app_handle(&self, app: tauri::AppHandle) {
        let mut configured_app = self.app.lock().expect("app handle poisoned");
        *configured_app = Some(app.clone());

        // Set up history file path in app_data_dir
        if let Ok(app_data_dir) = app.path().app_data_dir() {
            let history_file: PathBuf = app_data_dir.join("transfer_history.json");
            if let Ok(mut path) = self.history_path.lock() {
                *path = Some(history_file.clone());
            }
            // Load existing history
            self.load_history(&history_file);
        }
    }

    pub fn start(self: &Arc<Self>) {
        self.start_discovery_listener();
        self.start_beacon_loop();
        self.start_transfer_listener();
        self.start_ttl_cleanup_loop();
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
        let lost_ids: Vec<String> = state
            .devices
            .iter()
            .filter(|(_, device)| now.saturating_sub(device.last_seen_ms) > DEVICE_TTL_MS)
            .map(|(id, _)| id.clone())
            .collect();

        state
            .devices
            .retain(|_, device| now.saturating_sub(device.last_seen_ms) <= DEVICE_TTL_MS);
        drop(state);

        for id in &lost_ids {
            self.emit_device_lost(id.clone());
        }

        let state = self.state.lock().expect("network state poisoned");
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
        self.save_history();
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

    pub fn set_discovery_enabled(&self, enabled: bool) {
        let mut discovery = self.discovery_enabled.lock().expect("discovery state poisoned");
        let was_enabled = *discovery;
        *discovery = enabled;
        drop(discovery);
        if enabled {
            let mut last_new = self.last_new_device_ms.lock().expect("last_new_device_ms poisoned");
            *last_new = now_ms();
            drop(last_new);
            self.broadcast_beacon();
        } else if was_enabled {
            self.broadcast_goodbye();
        }
    }

    fn broadcast_beacon(&self) {
        if let Ok(payload) = serde_json::to_vec(&self.beacon()) {
            Self::send_discovery_burst(payload, "beacon");
        }
    }

    fn broadcast_probe(&self) {
        let probe = Probe {
            protocol: PROBE_PROTOCOL.to_string(),
        };
        if let Ok(payload) = serde_json::to_vec(&probe) {
            Self::send_discovery_burst(payload, "probe");
        }
    }

    fn broadcast_goodbye(&self) {
        let identity = self.identity();
        let goodbye = Goodbye {
            protocol: GOODBYE_PROTOCOL.to_string(),
            id: identity.id,
        };
        if let Ok(payload) = serde_json::to_vec(&goodbye) {
            Self::send_discovery_burst(payload, "goodbye");
        }
    }

    fn send_discovery_burst(payload: Vec<u8>, label: &'static str) {
        thread::spawn(move || {
            let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                Ok(socket) => socket,
                Err(error) => {
                    eprintln!("{label} bind failed: {error}");
                    return;
                }
            };
            if let Err(error) = socket.set_broadcast(true) {
                eprintln!("{label} set_broadcast failed: {error}");
            }
            let targets = discovery_targets();
            for _ in 0..DISCOVERY_BURST_COUNT {
                for target in &targets {
                    if let Err(error) = socket.send_to(&payload, target) {
                        eprintln!("{label} send to {target} failed: {error}");
                    }
                }
                thread::sleep(DISCOVERY_BURST_INTERVAL);
            }
        });
    }

    pub fn is_discovery_enabled(&self) -> bool {
        *self.discovery_enabled.lock().expect("discovery state poisoned")
    }

    pub fn probe_discovery(&self) {
        let lost_ids = self.clear_devices();
        for id in lost_ids {
            self.emit_device_lost(id);
        }
        if self.is_discovery_enabled() {
            self.broadcast_beacon();
        }
        self.broadcast_probe();
    }

    fn clear_devices(&self) -> Vec<String> {
        let mut state = self.state.lock().expect("network state poisoned");
        let lost_ids = state.devices.keys().cloned().collect::<Vec<_>>();
        state.devices.clear();
        lost_ids
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
            speed_mbps: 0.0,
            eta_seconds: 0,
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
                    speed_mbps: 0.0,
                    eta_seconds: 0,
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
                    speed_mbps: 0.0,
                    eta_seconds: 0,
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
                speed_mbps: 0.0,
                eta_seconds: 0,
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
                speed_mbps: 0.0,
                eta_seconds: 0,
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
            speed_mbps: 0.0,
            eta_seconds: 0,
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
                    speed_mbps: 0.0,
                    eta_seconds: 0,
                });
            }
        }

        Ok(crypto::encode_bytes(&hmac.finalize()))
    }

    fn start_discovery_listener(self: &Arc<Self>) {
        let service = self.clone();
        thread::spawn(move || {
            let socket = match discovery_socket() {
                Ok(socket) => socket,
                Err(error) => {
                    eprintln!("discovery bind failed: {error}");
                    return;
                }
            };
            let mut buffer = [0_u8; 2048];

            loop {
                let Ok((size, source)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                if !is_lan_ip(&source.ip()) {
                    continue;
                }

                if let Ok(probe) = serde_json::from_slice::<Probe>(&buffer[..size]) {
                    if probe.protocol == PROBE_PROTOCOL {
                        let discovery_enabled = service
                            .discovery_enabled
                            .lock()
                            .expect("discovery state poisoned");
                        if *discovery_enabled {
                            let reply_to = SocketAddr::new(source.ip(), DISCOVERY_PORT);
                            if let Ok(payload) = serde_json::to_vec(&service.beacon()) {
                                let _ = socket.send_to(&payload, reply_to);
                            }
                        }
                        continue;
                    }
                }

                // 处理 Goodbye 包（设备主动下线）
                if let Ok(goodbye) = serde_json::from_slice::<Goodbye>(&buffer[..size]) {
                    if goodbye.protocol == GOODBYE_PROTOCOL {
                        if goodbye.id != service.identity().id {
                            let mut state = service.state.lock().expect("network state poisoned");
                            let removed = state.devices.remove(&goodbye.id).is_some();
                            drop(state);
                            if removed {
                                service.emit_device_lost(goodbye.id);
                            }
                        }
                        continue;
                    }
                }

                let Ok(beacon) = serde_json::from_slice::<Beacon>(&buffer[..size]) else {
                    continue;
                };

                if beacon.protocol != PROTOCOL || beacon.id == service.identity().id {
                    continue;
                }

                let mut state = service.state.lock().expect("network state poisoned");
                let is_new = !state.devices.contains_key(&beacon.id);
                let device_info = DeviceInfo {
                    id: beacon.id.clone(),
                    name: beacon.name.clone(),
                    platform: beacon.platform.clone(),
                    address: source.ip().to_string(),
                    port: beacon.port,
                    last_seen_ms: now_ms(),
                    crypto_public_key: beacon.crypto_public_key.clone(),
                };
                state.devices.insert(beacon.id.clone(), device_info.clone());
                drop(state);

                if is_new {
                    service.emit_device_discovered(device_info);
                    let mut last_new = service.last_new_device_ms.lock().expect("last_new_device_ms poisoned");
                    *last_new = now_ms();
                }

                let discovery_enabled = service.discovery_enabled.lock().expect("discovery state poisoned");
                if *discovery_enabled {
                    let reply_to = SocketAddr::new(source.ip(), DISCOVERY_PORT);
                    if let Ok(payload) = serde_json::to_vec(&service.beacon()) {
                        let _ = socket.send_to(&payload, reply_to);
                    }
                }
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
                let discovery_enabled = service.discovery_enabled.lock().expect("discovery state poisoned");
                if !*discovery_enabled {
                    drop(discovery_enabled);
                    thread::sleep(BEACON_INTERVAL_FAST);
                    continue;
                }
                drop(discovery_enabled);

                if let Ok(payload) = serde_json::to_vec(&service.beacon()) {
                    for target in discovery_targets() {
                        let _ = socket.send_to(&payload, target);
                    }
                }

                let last_new = *service.last_new_device_ms.lock().expect("last_new_device_ms poisoned");
                let interval = if now_ms().saturating_sub(last_new) > BEACON_BACKOFF_THRESHOLD_MS {
                    BEACON_INTERVAL_SLOW
                } else {
                    BEACON_INTERVAL_FAST
                };
                thread::sleep(interval);
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

    fn start_ttl_cleanup_loop(self: &Arc<Self>) {
        let service = self.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(1));
                let _ = service.devices();
            }
        });
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
            speed_mbps: 0.0,
            eta_seconds: 0,
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
                    speed_mbps: 0.0,
                    eta_seconds: 0,
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
                speed_mbps: 0.0,
                eta_seconds: 0,
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
                speed_mbps: 0.0,
                eta_seconds: 0,
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
            speed_mbps: 0.0,
            eta_seconds: 0,
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
        drop(history);
        self.save_history();
    }

    fn load_history(&self, path: &PathBuf) {
        if !path.exists() {
            return;
        }
        match fs::read_to_string(path) {
            Ok(content) => {
                if let Ok(loaded) = serde_json::from_str::<Vec<TransferEvent>>(&content) {
                    let mut history = self.history.lock().expect("transfer history poisoned");
                    *history = loaded;
                    if history.len() > MAX_TRANSFER_HISTORY {
                        let overflow = history.len() - MAX_TRANSFER_HISTORY;
                        history.drain(0..overflow);
                    }
                }
            }
            Err(error) => {
                eprintln!("Failed to load transfer history: {}", error);
            }
        }
    }

    fn save_history(&self) {
        let path = match self.history_path.lock() {
            Ok(path) => path.clone(),
            Err(_) => return,
        };
        let path = match path {
            Some(path) => path,
            None => return,
        };
        let history = match self.history.lock() {
            Ok(history) => history.clone(),
            Err(_) => return,
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                eprintln!("Failed to create history directory: {}", error);
                return;
            }
        }
        match serde_json::to_string_pretty(&history) {
            Ok(content) => {
                if let Err(error) = fs::write(&path, content) {
                    eprintln!("Failed to save transfer history: {}", error);
                }
            }
            Err(error) => {
                eprintln!("Failed to serialize transfer history: {}", error);
            }
        }
    }

    fn emit_progress(&self, mut progress: TransferProgress) {
        let now = now_ms();
        let mut timestamps = self.progress_timestamps.lock().expect("progress timestamps poisoned");

        if progress.phase == TransferPhase::Started {
            timestamps.insert(progress.transfer_id.clone(), (now, progress.bytes_transferred));
        } else if progress.phase == TransferPhase::Progress {
            if let Some((last_time, last_bytes)) = timestamps.get(&progress.transfer_id) {
                let time_delta_ms = now.saturating_sub(*last_time) as f64;
                let bytes_delta = progress.bytes_transferred.saturating_sub(*last_bytes) as f64;

                if time_delta_ms > 100.0 && bytes_delta > 0.0 {
                    let speed_bps = bytes_delta / (time_delta_ms / 1000.0);
                    progress.speed_mbps = speed_bps / (1024.0 * 1024.0);

                    let remaining_bytes = progress.total_bytes.saturating_sub(progress.bytes_transferred) as f64;
                    if speed_bps > 0.0 {
                        progress.eta_seconds = (remaining_bytes / speed_bps) as u64;
                    }

                    timestamps.insert(progress.transfer_id.clone(), (now, progress.bytes_transferred));
                }
            }
        } else if progress.phase == TransferPhase::Finished || progress.phase == TransferPhase::Failed {
            timestamps.remove(&progress.transfer_id);
        }

        drop(timestamps);

        let app = self.app.lock().expect("app handle poisoned").clone();
        if let Some(app) = app {
            let _ = app.emit(TRANSFER_PROGRESS_EVENT, progress);
        }
    }

    fn emit_device_discovered(&self, device: DeviceInfo) {
        let app = self.app.lock().expect("app handle poisoned").clone();
        if let Some(app) = app {
            let _ = app.emit(DEVICE_DISCOVERED_EVENT, device);
        }
    }

    fn emit_device_lost(&self, device_id: String) {
        let app = self.app.lock().expect("app handle poisoned").clone();
        if let Some(app) = app {
            let _ = app.emit(DEVICE_LOST_EVENT, device_id);
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

fn discovery_socket() -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DISCOVERY_PORT).into())?;
    socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
    Ok(socket.into())
}

fn discovery_targets() -> Vec<SocketAddr> {
    let mut targets = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT),
        SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), DISCOVERY_PORT),
    ];

    targets.extend(ipv4_broadcast_addresses().into_iter().map(|address| {
        SocketAddr::new(IpAddr::V4(address), DISCOVERY_PORT)
    }));
    targets.sort();
    targets.dedup();
    targets
}

#[cfg(not(target_os = "android"))]
fn ipv4_broadcast_addresses() -> Vec<Ipv4Addr> {
    Vec::new()
}

#[cfg(target_os = "android")]
fn ipv4_broadcast_addresses() -> Vec<Ipv4Addr> {
    use std::ffi::CStr;
    use std::ptr;

    let mut addresses = Vec::new();
    unsafe {
        let mut ifaddr: *mut libc::ifaddrs = ptr::null_mut();
        if libc::getifaddrs(&mut ifaddr) != 0 {
            return addresses;
        }

        let mut cursor = ifaddr;
        while !cursor.is_null() {
            let item = &*cursor;
            if !item.ifa_addr.is_null()
                && !item.ifa_netmask.is_null()
                && (*item.ifa_addr).sa_family as i32 == libc::AF_INET
                && (item.ifa_flags & libc::IFF_UP as u32) != 0
                && (item.ifa_flags & libc::IFF_LOOPBACK as u32) == 0
            {
                let name = CStr::from_ptr(item.ifa_name);
                if name.to_bytes().starts_with(b"wlan") || name.to_bytes().starts_with(b"ap") {
                    let addr = *(item.ifa_addr as *const libc::sockaddr_in);
                    let mask = *(item.ifa_netmask as *const libc::sockaddr_in);
                    let ip = u32::from_be(addr.sin_addr.s_addr);
                    let netmask = u32::from_be(mask.sin_addr.s_addr);
                    let broadcast = Ipv4Addr::from((ip | !netmask).to_be_bytes());
                    addresses.push(broadcast);
                }
            }
            cursor = item.ifa_next;
        }
        libc::freeifaddrs(ifaddr);
    }
    addresses
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
