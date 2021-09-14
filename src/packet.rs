use crate::prelude::*;

pub const MAX_PACKET_BYTES: usize = 1472;

fn last_sent() -> SystemTime {
	SystemTime::now() - Duration::from_secs(settings().resend_delay + 1)
}

#[derive(Clone,Serialize,Deserialize)]
pub struct Packet { //layer 1 encryption
	pub to: PublicKey,
	#[serde(with="serde_256_array")]
	pub symm_key: [u8; KEY_BYTES], //symm key encrypted with to's public key
	pub data: Vec<u8>, //message encrypted with symm_key
	#[serde(skip)]
	pub relative_key: [u8; HASH_BYTES],
	#[serde(skip,default="last_sent")]
	pub last_sent: SystemTime,
}

impl Packet {
	pub fn decrypt(self, key: &PrivateKey) -> Option<Message> {
		if let Some(key) = SymmetricKey::from_buf(&self.symm_key, key) {
			let data = key.decrypt(&self.data);
			if let Ok(msg) = deserialize::<Message>(&data) {
				if msg.from.verify(msg.signature, &msg.hash(), &self.to) {
					Some(msg)
				} else {
					None
				}
			} else {
				None
			}
		} else {
			None
		}
	}
	
	pub fn encrypt(to: PublicKey, msg: &Message) -> Self {
		let symm_key = SymmetricKey::new();
		let data = serialize(msg);
		let data = symm_key.encrypt(&data);
		Self {
			relative_key: to.relative_to(&msg.from),
			symm_key: to.encrypt(&symm_key.0).try_into().expect("wrong size vec when encrypting"),
			to,
			data,
			last_sent: SystemTime::now() - Duration::from_secs(settings().resend_delay),
		}
	}
}

#[derive(Clone,Serialize,Deserialize)]
pub struct RawPacket { //layer 2 encryption
	#[serde(with="serde_256_array")]
	pub symm_key: [u8; KEY_BYTES], //symm key encrypted with rsa
	pub data: Vec<u8>, //data encrypted with the symm key
}

impl RawPacket {
	pub fn encrypt(packet: &Packet, key: &PublicKey) -> Self {
		let symm_key = SymmetricKey::new();
		let data = serialize(packet);
		let data = symm_key.encrypt(&data);
		Self {
			symm_key: key.encrypt(&symm_key.0).try_into().expect("wrong size vec when encrypting"),
			data,
		}
	}
	
	pub fn decrypt(&self, key: &PrivateKey) -> Option<Packet> {
		if let Some(key) = SymmetricKey::from_buf(&self.symm_key, key) {
			let data = key.decrypt(&self.data);
			deserialize(&data).ok()
		} else {
			None
		}
	}
}

mod serde_256_array {
	//TODO fix this hack that probably breaks when endianness is different
	use serde::{Serialize,Deserialize,Serializer,Deserializer};
	pub fn serialize<S: Serializer>(x: &[u8; 256], serializer: S) -> Result<S::Ok, S::Error> {
		let x: &[u64; 32] = unsafe { std::mem::transmute(x) };
		x.serialize(serializer)
	}
	
	pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 256], D::Error> {
		let x = <[u64; 32]>::deserialize(deserializer)?;
		Ok(unsafe { std::mem::transmute(x) })
	}
}
