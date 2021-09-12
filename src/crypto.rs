use crate::prelude::*;

pub use crate::hash::*;

pub struct PrivateKey([u8; 1]);
#[derive(Copy,Clone,Serialize,Deserialize)]
pub struct PublicKey([u8; 1]);

impl PrivateKey {
	pub fn from_phrase(_data: &[u8]) -> (Self, PublicKey) {
		unimplemented!()
	}
	
	pub fn sign(&self, _data: &[u8]) -> Vec<u8> {
		unimplemented!()
	}
	
	pub fn decrypt(&self, _data: &[u8]) -> Vec<u8> {
		unimplemented!()
	}
}

impl PublicKey {
	pub fn encrypt(self, _data: &[u8]) -> Vec<u8> {
		unimplemented!()
	}
	
	pub fn relative_to(self, _other: Self) -> u64 {
		unimplemented!()
	}
	
	pub fn pop_bytes(buf: &mut Vec<u8>) -> Self {
		let mut r = PublicKey(Default::default());
		for i in (0..r.0.len()).rev() {
			r.0[i] = buf.pop().unwrap();
		}
		r
	}
	
	pub fn push_bytes(self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.0)
	}
}
