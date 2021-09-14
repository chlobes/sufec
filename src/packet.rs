use crate::prelude::*;

pub const MAX_PACKET_BYTES: usize = 1472;

#[derive(Clone,Serialize,Deserialize)]
pub struct Packet {
	pub to: PublicKey,
	#[serde(skip)]
	pub relative_key: [u8; HASH_BYTES],
	pub data: Vec<u8>,
	#[serde(skip,default="SystemTime::now")]
	pub last_sent: SystemTime,
}

impl Packet {
	pub fn from_bytes(data: Vec<u8>, priv_key: &PrivateKey, pub_key: &PublicKey) -> Option<Self> { //decrypt packet (2nd layer)
		let mut data = priv_key.decrypt(data).unwrap_or(Vec::new());
		if data.len() < mem::size_of::<PublicKey>() { return None; }
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
		let r = key.encrypt(&self.data);
		if r.len() > MAX_PACKET_BYTES {
			println!("error packet is too large: {}",r.len());
		}
		r
	}
	
	pub fn decrypt(self, key: &PrivateKey) -> Option<Message> { //decypt inner message (1st layer)
		if self.data.len() < key.min_decrypt_len() { return None; }
		let mut data = key.decrypt(self.data).unwrap_or(Vec::new());
		let mut signature = [0; SIGNATURE_BYTES];
		if data.len() < signature.len() { return None; }
		for i in (0..signature.len()).rev() {
			signature[i] = data.pop().unwrap();
		}
		if let Ok(message) = deserialize::<Message>(&data) {
			if message.from.verify(signature, &data) {
				Some(message)
			} else {
				None
			}
		} else {
			None
		}
	}
	
	pub fn encrypt(from: (&PrivateKey, &PublicKey), to: PublicKey, msg: &Message) -> Self { //encrypt the inner message and construct a packet out of it (1st layer)
		let mut data = serialize(msg);
		let signature = from.0.sign(&data, &to);
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
