use crate::prelude::*;

pub const PACKET_SIZE: usize = 512;
pub const PORT: u16 = 36107;

#[derive(Clone)]
pub struct Packet {
	pub to: PublicKey,
	pub data: Vec<u8>,
}

impl Packet {
	pub fn from_bytes(data: &[u8], key: &PrivateKey) -> Option<Self> {
		if data.len() < mem::size_of::<PublicKey>() { return None; }
		let mut data = key.decrypt(data);
		let to = PublicKey::pop_bytes(&mut data);
		Some(Self {
			to,
			data,
		})
	}
	
	pub fn to_bytes(mut self, key: PublicKey) -> Vec<u8> {
		self.to.push_bytes(&mut self.data);
		key.encrypt(&self.data)
	}
	
	pub fn decrypt(&self, key: &PrivateKey) -> Option<Message> {
		let data = key.decrypt(&self.data);
		use flate2::read::DeflateDecoder;
		let mut d = DeflateDecoder::new(data.as_slice());
		let mut data = Vec::new();
		let _ = d.read_to_end(&mut data);
		deserialize(&data).ok()
	}
	
	pub fn encrypt(from: &PrivateKey, to: PublicKey, msg: &Message) -> Self {
		let data = serialize(msg);
		let data = from.sign(&data);
		use flate2::{Compression,write::DeflateEncoder};
		let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
		e.write_all(&data).unwrap();
		let data = e.finish().unwrap();
		let data = to.encrypt(&data);
		Self {
			to,
			data,
		}
	}
}
