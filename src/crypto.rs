use crate::prelude::*;

pub use crate::hash::*;

use rsa::{PublicKey as RsaPublicKeyTrait,RsaPrivateKey,RsaPublicKey,PaddingScheme};
use rand::{Rng,SeedableRng,rngs::{OsRng,StdRng}};

pub const KEY_BITS: usize = 2048;
pub const KEY_BYTES: usize = KEY_BITS / 8;
pub const SIGNATURE_BYTES: usize = 64;
pub const SYMMETRIC_KEY_BYTES: usize = HASH_BYTES;

pub struct PrivateKey(RsaPrivateKey);
#[derive(Clone,Serialize,Deserialize,Eq,PartialEq,Debug)]
pub struct PublicKey(RsaPublicKey);

#[derive(Copy,Clone,Eq,PartialEq)]
pub struct SymmetricKey(pub [u8; SYMMETRIC_KEY_BYTES]);

impl PrivateKey {
	pub fn from_phrase(data: &[u8]) -> (Self, PublicKey) {
		let mut rng = StdRng::from_seed(hash(data));
		let s = RsaPrivateKey::new(&mut rng, KEY_BITS).expect("failed to generate rsa private key");
		let p = PublicKey(RsaPublicKey::from(&s));
		(PrivateKey(s), p)
	}
	
	pub fn sign(&self, _data: &[u8], _to: &PublicKey) -> [u8; SIGNATURE_BYTES] { //TODO
		[0; SIGNATURE_BYTES]
	}
	
	pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		self.0.decrypt(padding, &data).ok()
	}
}

impl PublicKey {
	pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		let data = self.0.encrypt(&mut OsRng, padding, data).expect("failed to encrypt");
		debug_assert!(data.len() == KEY_BYTES);
		data
	}
	
	pub fn verify(&self, _signature: [u8; SIGNATURE_BYTES], _data: &[u8], _to: &PublicKey) -> bool { //TODO
		true
	}
	
	pub fn relative_to(&self, other: &Self) -> [u8; 32] {
		let mut r = [0; HASH_BYTES];
		let a = hash(&serialize(&self.0));
		let b = hash(&serialize(&other.0));
		let mut carry = 0;
		for i in (0..HASH_BYTES).rev() {
			let (v, c1) = a[i].overflowing_sub(b[i]);
			let (v, c2) = v.overflowing_sub(carry);
			r[i] = v;
			carry = (c1 || c2) as u8;
		}
		r
	}
}

impl SymmetricKey {
	pub fn new() -> Self {
		let mut r = SymmetricKey(Default::default());
		OsRng.fill(&mut r.0);
		r
	}
	
	pub fn from_buf(buf: &[u8], key: &PrivateKey) -> Option<Self> {
		key.decrypt(buf)
			.and_then(|buf| buf.try_into().ok())
			.map(|buf| SymmetricKey(buf))
	}
	
	pub fn encrypt(mut self, data: &[u8]) -> Vec<u8> {
		let mut result = Vec::new();
		for chunk in data.chunks(self.0.len()) {
			for i in 0..chunk.len() {
				result.push(chunk[i] ^ self.0[i]);
			}
			self.0 = hash(&self.0);
		}
		result
	}
	
	pub fn decrypt(self, data: &[u8]) -> Vec<u8> {
		self.encrypt(data) //the process is symmetric
	}
}
