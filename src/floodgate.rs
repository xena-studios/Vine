//! Floodgate handoff from Geyser, verified natively.
//!
//! Geyser with `auth-type: floodgate` appends Floodgate's encrypted player data to the
//! handshake's server address, after a `\0`. Floodgate (a Java plugin) normally reads it on
//! the proxy or server; Vine can't run Java plugins, so it reads the same format here:
//!
//! - The address is split on `\0`. The first part that starts with [`IDENTIFIER`] and a
//!   version char is the data; the rest, joined again with `\0`, is the real address.
//! - Data is [`HEADER`] + base64(iv, 12 bytes) + `!` + base64(AES-128-GCM ciphertext and its
//!   128-bit tag). The key is the raw 16 bytes of Floodgate's `key.pem` (it isn't PEM).
//! - The plaintext is 12 fields split by `\0` ([`BedrockData`]).
//!
//! This follows GeyserMC's `common/.../floodgate/crypto/AesCipher.java`,
//! `util/BedrockData.java` and Floodgate's `FloodgateHandshakeHandler` and
//! `HandshakeDataImpl`.

use std::net::IpAddr;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// `^Floodgate^`, the start of every handoff.
pub const IDENTIFIER: &str = "^Floodgate^";
/// The only data version Floodgate has: 0, written as `char(0 + 0x3E)`, so `>`.
pub const VERSION: u32 = 0;
/// [`IDENTIFIER`] plus the version char.
pub const HEADER: &str = "^Floodgate^>";
const IV_LENGTH: usize = 12;
const SPLITTER: u8 = b'!';
/// Fields in the plaintext; Floodgate refuses any other count.
pub const EXPECTED_LENGTH: usize = 12;

fn default_key_file() -> String {
    "key.pem".to_string()
}

fn default_username_prefix() -> String {
    ".".to_string()
}

fn default_true() -> bool {
    true
}

/// `[floodgate]` in `vine.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FloodgateConfig {
    /// Read Floodgate handoffs at all. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Floodgate's key, the same file Geyser's `floodgate-key-file` points at.
    #[serde(default = "default_key_file")]
    pub key_file: String,
    /// Put before every Bedrock username, as Floodgate's `username-prefix` does, so Bedrock
    /// and Java names can't clash. The result is cut to 16 characters.
    #[serde(default = "default_username_prefix")]
    pub username_prefix: String,
    /// Replace spaces in Bedrock usernames with `_`, as Floodgate's `replace-spaces` does.
    #[serde(default = "default_true")]
    pub replace_spaces: bool,
    /// An extra listener for Geyser only: every login on it must carry a valid handoff.
    /// It never expects a PROXY protocol header and isn't rate limited per address (every
    /// connection comes from Geyser); the player's own address comes from the handoff.
    #[serde(default)]
    pub bind_address: Option<String>,
    /// Require a valid handoff on the main listener too (a proxy only Geyser reaches).
    #[serde(default)]
    pub required: bool,
}

impl Default for FloodgateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_file: default_key_file(),
            username_prefix: default_username_prefix(),
            replace_spaces: true,
            bind_address: None,
            required: false,
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum FloodgateError {
    #[error("key must be 16 bytes (AES-128), got {0}")]
    InvalidKeyLength(usize),
    #[error("unsupported Floodgate data version {0}")]
    UnsupportedVersion(u32),
    #[error("no '!' between the iv and the ciphertext")]
    MissingSplitter,
    #[error("invalid base64")]
    InvalidBase64,
    #[error("iv must be {IV_LENGTH} bytes, got {0}")]
    InvalidIvLength(usize),
    #[error("decryption failed (wrong key or tampered data)")]
    DecryptFailed,
    #[error("plaintext is not UTF-8")]
    InvalidUtf8,
    #[error("expected {EXPECTED_LENGTH} fields, got {0}")]
    InvalidDataLength(usize),
    #[error("invalid field '{0}'")]
    InvalidField(&'static str),
}

/// Floodgate's shared AES-128 key.
#[derive(Clone)]
pub struct FloodgateKey {
    cipher: Aes128Gcm,
}

impl std::fmt::Debug for FloodgateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FloodgateKey(..)")
    }
}

impl FloodgateKey {
    /// From the raw key bytes (the whole `key.pem` file).
    pub fn from_bytes(key: &[u8]) -> Result<Self, FloodgateError> {
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|_| FloodgateError::InvalidKeyLength(key.len()))?;
        Ok(Self { cipher })
    }

    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Decrypts one handoff (starting with [`HEADER`]) to its plaintext.
    pub fn decrypt(&self, data: &str) -> Result<String, FloodgateError> {
        let version = data_version(data).ok_or(FloodgateError::UnsupportedVersion(u32::MAX))?;
        if version != VERSION {
            return Err(FloodgateError::UnsupportedVersion(version));
        }
        let body = &data.as_bytes()[HEADER.len()..];
        let split = body
            .iter()
            .position(|&b| b == SPLITTER)
            .ok_or(FloodgateError::MissingSplitter)?;
        let iv = STANDARD
            .decode(&body[..split])
            .map_err(|_| FloodgateError::InvalidBase64)?;
        let iv: [u8; IV_LENGTH] = iv
            .try_into()
            .map_err(|iv: Vec<u8>| FloodgateError::InvalidIvLength(iv.len()))?;
        let ciphertext = STANDARD
            .decode(&body[split + 1..])
            .map_err(|_| FloodgateError::InvalidBase64)?;
        let plaintext = self
            .cipher
            .decrypt(&Nonce::from(iv), ciphertext.as_slice())
            .map_err(|_| FloodgateError::DecryptFailed)?;
        String::from_utf8(plaintext).map_err(|_| FloodgateError::InvalidUtf8)
    }

    /// Encrypts a plaintext the way Geyser does. Used by tests and tools.
    pub fn encrypt(&self, plaintext: &str, iv: [u8; IV_LENGTH]) -> String {
        let ciphertext = self
            .cipher
            .encrypt(&Nonce::from(iv), plaintext.as_bytes())
            .expect("AES-GCM encryption of a short buffer can't fail");
        format!(
            "{HEADER}{}!{}",
            STANDARD.encode(iv),
            STANDARD.encode(ciphertext)
        )
    }
}

/// The data version of a part that starts with [`IDENTIFIER`], like Floodgate's
/// `FloodgateCipher.version`: `None` if it doesn't look like Floodgate data at all.
pub fn data_version(part: &str) -> Option<u32> {
    if part.len() <= HEADER.len() || !part.starts_with(IDENTIFIER) {
        return None;
    }
    let version_char = part[IDENTIFIER.len()..].chars().next()?;
    (version_char as u32).checked_sub(0x3E)
}

/// A handshake address split into the Floodgate data (if any) and the real address.
#[derive(Debug, PartialEq, Eq)]
pub struct SeparatedHostname<'a> {
    pub data: Option<&'a str>,
    pub hostname: String,
}

/// Floodgate's `separateHostname`: the first part with Floodgate's header is the data; every
/// other part is joined again with `\0`.
pub fn separate_hostname(address: &str) -> SeparatedHostname<'_> {
    let mut data = None;
    let mut rest: Vec<&str> = Vec::new();
    for part in java_split(address, '\0') {
        if data.is_none() && data_version(part).is_some() {
            data = Some(part);
        } else {
            rest.push(part);
        }
    }
    SeparatedHostname {
        data,
        hostname: rest.join("\0"),
    }
}

/// Java's `String.split`, which drops trailing empty strings. Floodgate counts fields that
/// way, so a handoff whose last field is empty has 11 fields and is refused.
fn java_split(s: &str, sep: char) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split(sep).collect();
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts == [""] && !s.is_empty() {
        parts.clear();
    }
    parts
}

/// A Bedrock player linked to a Java account (Floodgate's `LinkedPlayer`), sent when another
/// proxy already looked the link up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedPlayer {
    pub java_username: String,
    pub java_uuid: Uuid,
    pub bedrock_uuid: Uuid,
}

/// Floodgate's `BedrockData`, in the field order Geyser writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BedrockData {
    /// The Bedrock client's game version, e.g. `1.26.60`.
    pub version: String,
    /// The Xbox gamertag, before the prefix.
    pub username: String,
    pub xuid: String,
    /// Floodgate's `DeviceOs` ordinal (see [`device_os_name`]).
    pub device_os: i32,
    pub language_code: String,
    /// Field 5. Floodgate calls it the UI profile, but Geyser's `BedrockData.of` swaps its
    /// arguments, so it carries the input mode.
    pub ui_profile: i32,
    /// Field 6, really the UI profile (see [`Self::ui_profile`]).
    pub input_mode: i32,
    /// The Bedrock player's address as Geyser saw it.
    pub ip: String,
    pub linked_player: Option<LinkedPlayer>,
    pub from_proxy: bool,
    pub subscribe_id: i32,
    pub verify_code: String,
}

impl BedrockData {
    /// Floodgate's `BedrockData.fromString`.
    pub fn parse(plaintext: &str) -> Result<Self, FloodgateError> {
        let f = java_split(plaintext, '\0');
        if f.len() != EXPECTED_LENGTH {
            return Err(FloodgateError::InvalidDataLength(f.len()));
        }
        let int = |i: usize, name: &'static str| {
            f[i].parse::<i32>()
                .map_err(|_| FloodgateError::InvalidField(name))
        };
        Ok(Self {
            version: f[0].to_string(),
            username: f[1].to_string(),
            xuid: f[2].to_string(),
            device_os: int(3, "deviceOs")?,
            language_code: f[4].to_string(),
            ui_profile: int(5, "uiProfile")?,
            input_mode: int(6, "inputMode")?,
            ip: f[7].to_string(),
            linked_player: parse_linked_player(f[8])?,
            from_proxy: f[9] == "1",
            subscribe_id: int(10, "subscribeId")?,
            verify_code: f[11].to_string(),
        })
    }

    /// Floodgate's `BedrockData.toString`, which Geyser encrypts.
    pub fn to_plaintext(&self) -> String {
        let linked = self.linked_player.as_ref().map_or_else(
            || "null".to_string(),
            |l| format!("{};{};{}", l.java_username, l.java_uuid, l.bedrock_uuid),
        );
        [
            self.version.clone(),
            self.username.clone(),
            self.xuid.clone(),
            self.device_os.to_string(),
            self.language_code.clone(),
            self.ui_profile.to_string(),
            self.input_mode.to_string(),
            self.ip.clone(),
            linked,
            if self.from_proxy { "1" } else { "0" }.to_string(),
            self.subscribe_id.to_string(),
            self.verify_code.clone(),
        ]
        .join("\0")
    }
}

/// Floodgate's `LinkedPlayer.fromString`: anything that isn't three `;` parts (`null`) is no
/// link; three parts with a bad UUID is an error, as in Java.
fn parse_linked_player(field: &str) -> Result<Option<LinkedPlayer>, FloodgateError> {
    let parts = java_split(field, ';');
    if parts.len() != 3 {
        return Ok(None);
    }
    let uuid =
        |s: &str| Uuid::parse_str(s).map_err(|_| FloodgateError::InvalidField("linkedPlayer"));
    Ok(Some(LinkedPlayer {
        java_username: parts[0].to_string(),
        java_uuid: uuid(parts[1])?,
        bedrock_uuid: uuid(parts[2])?,
    }))
}

/// Floodgate's `DeviceOs` names, by ordinal (`common/.../floodgate/util/DeviceOs.java`).
pub fn device_os_name(ordinal: i32) -> &'static str {
    const NAMES: [&str; 13] = [
        "Unknown",
        "Android",
        "iOS",
        "macOS",
        "Amazon",
        "Gear VR",
        "Windows",
        "Windows x86",
        "Dedicated",
        "PlayStation",
        "Switch",
        "Xbox",
        "Linux",
    ];
    usize::try_from(ordinal)
        .ok()
        .and_then(|i| NAMES.get(i))
        .copied()
        .unwrap_or("Unknown")
}

/// A Bedrock player who joined through Geyser with a valid handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BedrockPlayer {
    pub data: BedrockData,
    /// The name backends and plugins see: the link's Java name, or prefix + gamertag.
    pub java_username: String,
    /// The link's Java UUID, or Floodgate's `new UUID(0, xuid)`.
    pub java_uuid: Uuid,
    /// The player's address from the handoff.
    pub ip: IpAddr,
}

impl BedrockPlayer {
    /// The Java identity Floodgate gives this player (`HandshakeDataImpl`).
    pub fn from_data(data: BedrockData, config: &FloodgateConfig) -> Result<Self, FloodgateError> {
        let xuid: i64 = data
            .xuid
            .parse()
            .map_err(|_| FloodgateError::InvalidField("xuid"))?;
        let ip: IpAddr = data
            .ip
            .parse()
            .map_err(|_| FloodgateError::InvalidField("ip"))?;
        if data.username.is_empty() {
            return Err(FloodgateError::InvalidField("username"));
        }
        let (java_username, java_uuid) = match &data.linked_player {
            Some(link) => (link.java_username.clone(), link.java_uuid),
            None => (prefixed_username(&data.username, config), java_uuid(xuid)),
        };
        Ok(Self {
            data,
            java_username,
            java_uuid,
            ip,
        })
    }

    /// Decrypts, parses and checks one handoff.
    pub fn from_handoff(
        key: &FloodgateKey,
        handoff: &str,
        config: &FloodgateConfig,
    ) -> Result<Self, FloodgateError> {
        let plaintext = key.decrypt(handoff)?;
        Self::from_data(BedrockData::parse(&plaintext)?, config)
    }
}

/// Floodgate's `Utils.getJavaUuid`: `new UUID(0, xuid)`.
pub fn java_uuid(xuid: i64) -> Uuid {
    Uuid::from_u64_pair(0, xuid as u64)
}

/// Prefix + gamertag cut so the whole is at most 16 characters (Java `String` length, which
/// counts UTF-16 units; gamertags are ASCII), then spaces replaced if configured.
pub fn prefixed_username(username: &str, config: &FloodgateConfig) -> String {
    let prefix = &config.username_prefix;
    let room = 16usize.saturating_sub(prefix.encode_utf16().count());
    let mut taken = 0;
    let mut name = prefix.clone();
    for ch in username.chars() {
        taken += ch.len_utf16();
        if taken > room {
            break;
        }
        name.push(ch);
    }
    if config.replace_spaces {
        name = name.replace(' ', "_");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors made with Geyser's logic: `AesCipher.encrypt` with a `Base64Topping`, over
    // `BedrockData.toString()`. The key and iv are fixed so the bytes are reproducible.
    const KEY: [u8; 16] = *b"hallow-floodgate";
    const IV: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    fn sample() -> BedrockData {
        BedrockData {
            version: "1.26.60".into(),
            username: "Bedrock Steve".into(),
            xuid: "2535437563482741".into(),
            device_os: 1,
            language_code: "en_US".into(),
            ui_profile: 0,
            input_mode: 2,
            ip: "203.0.113.7".into(),
            linked_player: None,
            from_proxy: false,
            subscribe_id: -1,
            verify_code: "null".into(),
        }
    }

    fn config() -> FloodgateConfig {
        FloodgateConfig {
            enabled: true,
            ..FloodgateConfig::default()
        }
    }

    #[test]
    fn plaintext_matches_floodgate_format() {
        assert_eq!(
            sample().to_plaintext(),
            "1.26.60\0Bedrock Steve\x002535437563482741\x001\0en_US\x000\x002\x00203.0.113.7\0null\x000\0-1\0null"
        );
    }

    #[test]
    fn known_vector_decrypts() {
        // AES-128-GCM of the plaintext above under KEY and IV, base64 as Geyser writes it.
        let key = FloodgateKey::from_bytes(&KEY).unwrap();
        let handoff = key.encrypt(&sample().to_plaintext(), IV);
        assert!(handoff.starts_with("^Floodgate^>AQIDBAUGBwgJCgsM!"));
        assert_eq!(key.decrypt(&handoff).unwrap(), sample().to_plaintext());
        assert_eq!(handoff, KNOWN_HANDOFF);
    }

    /// Made by Java's `Cipher.getInstance("AES/GCM/NoPadding")` with Geyser's
    /// `AesCipher.encrypt` layout, KEY and IV, over `sample().to_plaintext()`.
    const KNOWN_HANDOFF: &str = "^Floodgate^>AQIDBAUGBwgJCgsM!5sRXO4sK6ckNMN14d/lhPnDpGZ+/kkEsRUyJs/MWoOyM791PRBlLFlF4EaLidjiuYCxzrZbSH0fr9J+Eu6xLnYoI5oTXNdMtsFQvSi8d6l6n6RiHYIAsTMt2mtZ4";

    #[test]
    fn identity_like_floodgate() {
        let key = FloodgateKey::from_bytes(&KEY).unwrap();
        let handoff = key.encrypt(&sample().to_plaintext(), IV);
        let player = BedrockPlayer::from_handoff(&key, &handoff, &config()).unwrap();
        assert_eq!(player.java_username, ".Bedrock_Steve");
        assert_eq!(
            player.java_uuid.to_string(),
            "00000000-0000-0000-0009-01f78f525275"
        );
        assert_eq!(player.ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(player.data, sample());
    }

    #[test]
    fn java_uuid_is_zero_then_xuid() {
        let uuid = java_uuid(2535437563482741);
        let (hi, lo) = uuid.as_u64_pair();
        assert_eq!(hi, 0);
        assert_eq!(lo, 2535437563482741);
    }

    #[test]
    fn username_is_cut_to_sixteen_with_prefix() {
        let cfg = config();
        assert_eq!(
            prefixed_username("ABCDEFGHIJKLMNOPQRS", &cfg),
            ".ABCDEFGHIJKLMNO"
        );
        assert_eq!(prefixed_username("ABCDEFGHIJKLMNOPQRS", &cfg).len(), 16);
        let no_prefix = FloodgateConfig {
            username_prefix: String::new(),
            replace_spaces: false,
            ..cfg
        };
        assert_eq!(prefixed_username("A B", &no_prefix), "A B");
    }

    #[test]
    fn linked_player_uses_java_identity() {
        let mut data = sample();
        data.linked_player = Some(LinkedPlayer {
            java_username: "Steve".into(),
            java_uuid: Uuid::parse_str("069a79f4-44e9-4726-a5be-fca90e38aaf5").unwrap(),
            bedrock_uuid: java_uuid(2535437563482741),
        });
        let parsed = BedrockData::parse(&data.to_plaintext()).unwrap();
        assert_eq!(parsed, data);
        let player = BedrockPlayer::from_data(parsed, &config()).unwrap();
        assert_eq!(player.java_username, "Steve");
        assert_eq!(
            player.java_uuid.to_string(),
            "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        );
    }

    #[test]
    fn separates_hostname() {
        let sep = separate_hostname("play.example.com\0^Floodgate^>abc!def");
        assert_eq!(sep.data, Some("^Floodgate^>abc!def"));
        assert_eq!(sep.hostname, "play.example.com");

        let sep = separate_hostname("a\0^Floodgate^>x\0b\0^Floodgate^>y");
        assert_eq!(sep.data, Some("^Floodgate^>x"));
        assert_eq!(sep.hostname, "a\0b\0^Floodgate^>y");

        let sep = separate_hostname("play.example.com");
        assert_eq!(sep.data, None);
        assert_eq!(sep.hostname, "play.example.com");

        // Just the header isn't data (`version` needs more than the header).
        assert_eq!(separate_hostname("h\0^Floodgate^>").data, None);
    }

    #[test]
    fn wrong_key_or_tampering_is_refused() {
        let key = FloodgateKey::from_bytes(&KEY).unwrap();
        let other = FloodgateKey::from_bytes(b"0123456789abcdef").unwrap();
        let handoff = key.encrypt(&sample().to_plaintext(), IV);
        assert_eq!(other.decrypt(&handoff), Err(FloodgateError::DecryptFailed));

        // Flip one base64 char of the ciphertext.
        let mut bytes = handoff.into_bytes();
        let last = bytes.len() - 3;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert_eq!(key.decrypt(&tampered), Err(FloodgateError::DecryptFailed));

        assert_eq!(
            key.decrypt("^Floodgate^>nosplitter"),
            Err(FloodgateError::MissingSplitter)
        );
        assert_eq!(
            key.decrypt("^Floodgate^?AAAA!AAAA"),
            Err(FloodgateError::UnsupportedVersion(1))
        );
        assert_eq!(
            key.decrypt("^Floodgate^>AAAA!AAAA"),
            Err(FloodgateError::InvalidIvLength(3))
        );
    }

    #[test]
    fn field_count_must_be_twelve() {
        let key = FloodgateKey::from_bytes(&KEY).unwrap();
        let eleven = "a\0b\0c\0d\0e\0f\0g\0h\0i\0j\0k";
        assert_eq!(
            BedrockPlayer::from_handoff(&key, &key.encrypt(eleven, IV), &config()),
            Err(FloodgateError::InvalidDataLength(11))
        );
        // A trailing empty field is dropped, as Java's split does.
        let mut data = sample();
        data.verify_code = String::new();
        assert_eq!(
            BedrockData::parse(&data.to_plaintext()),
            Err(FloodgateError::InvalidDataLength(11))
        );
        let thirteen = format!("{}\0extra", sample().to_plaintext());
        assert_eq!(
            BedrockData::parse(&thirteen),
            Err(FloodgateError::InvalidDataLength(13))
        );
    }

    #[test]
    fn bad_fields_are_refused() {
        let mut data = sample();
        data.xuid = "not-a-number".into();
        assert_eq!(
            BedrockPlayer::from_data(data, &config()),
            Err(FloodgateError::InvalidField("xuid"))
        );
        let mut data = sample();
        data.ip = "nowhere".into();
        assert_eq!(
            BedrockPlayer::from_data(data, &config()),
            Err(FloodgateError::InvalidField("ip"))
        );
        let bad_int = sample().to_plaintext().replacen("\x001\0", "\0x\0", 1);
        assert_eq!(
            BedrockData::parse(&bad_int),
            Err(FloodgateError::InvalidField("deviceOs"))
        );
    }

    #[test]
    fn config_from_toml() {
        let cfg: FloodgateConfig = toml::from_str(
            r#"
            enabled = true
            key_file = "floodgate/key.pem"
            bind_address = "0.0.0.0:25567"
            "#,
        )
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.key_file, "floodgate/key.pem");
        assert_eq!(cfg.username_prefix, ".");
        assert!(cfg.replace_spaces);
        assert_eq!(cfg.bind_address.as_deref(), Some("0.0.0.0:25567"));
        assert!(!cfg.required);
        assert!(!FloodgateConfig::default().enabled);
    }

    #[test]
    fn key_must_be_sixteen_bytes() {
        assert_eq!(
            FloodgateKey::from_bytes(&[0u8; 32]).unwrap_err(),
            FloodgateError::InvalidKeyLength(32)
        );
    }
}
