use crate::prelude::*;

pub const PACKET_SIZE: usize = 512;

#[derive(Clone,Serialize,Deserialize)]
pub struct Packet {
	pub to: PublicKey,
	#[serde(skip)]
	pub relative_key: [u8; HASH_SIZE],
	pub data: Vec<u8>,
	#[serde(skip,default="SystemTime::now")]
	pub last_sent: SystemTime,
}

impl Packet {
	pub fn from_bytes(data: &[u8], priv_key: &PrivateKey, pub_key: &PublicKey) -> Option<Self> { //decrypt packet (2nd layer)
		if data.len() < mem::size_of::<PublicKey>() { return None; }
		let mut data = priv_key.decrypt(data);
		let to = PublicKey::pop_bytes(&mut data);
		Some(Self {
			relative_key: to.relative_to(pub_key),
			to,
			data,
			last_sent: SystemTime::now() - Duration::from_secs(settings().resend_delay),
		})
	}
	
	pub fn to_bytes(&self, key: &PublicKey) -> Vec<u8> { //encrypt it as a bytestream for the target public key (2nd layer)
		let mut data = self.data.clone();
		self.to.push_bytes(&mut data);
		key.encrypt(&self.data)
	}
	
	pub fn decrypt(&self, key: &PrivateKey) -> Option<Message> { //decypt inner message (1st layer)
		let mut data = key.decrypt(&self.data);
		let mut signature = [0; SIGNATURE_SIZE];
		if data.len() > signature.len() {
			for i in (0..signature.len()).rev() {
				signature[i] = data.pop().unwrap();
			}
			use flate2::read::DeflateDecoder;
			let mut d = DeflateDecoder::new(data.as_slice());
			let mut data = Vec::new();
			let _ = d.read_to_end(&mut data);
			if let Ok(message) = deserialize::<Message>(&data) {
				if message.from.verify(signature, &data) {
					Some(message)
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
	
	pub fn encrypt(from: (&PrivateKey, &PublicKey), to: PublicKey, msg: &Message) -> Self { //encrypt the inner message and construct a packet out of it (1st layer)
		let mut data = serialize(msg);
		use flate2::{Compression,write::DeflateEncoder};
		let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
		e.write_all(&data).unwrap();
		let mut data = e.finish().unwrap();
		let signature = from.0.sign(&data);
		data.extend_from_slice(&signature);
		let data = to.encrypt(&data);
		Self {
			relative_key: to.relative_to(from.1),
			to,
			data,
			last_sent: SystemTime::now() - Duration::from_secs(settings().resend_delay),
		}
	}
}
