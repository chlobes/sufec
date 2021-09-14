use crate::prelude::*;

pub use crate::hash::*;

use rsa::{PublicKey as RsaPublicKeyTrait,RsaPrivateKey,RsaPublicKey,PaddingScheme};

pub const KEY_BITS: usize = 2048;
pub const SIGNATURE_BYTES: usize = 64;

pub struct PrivateKey(RsaPrivateKey);
#[derive(Clone,Serialize,Deserialize,Eq,PartialEq,Debug)]
pub struct PublicKey(RsaPublicKey);

impl PrivateKey {
	pub fn from_phrase(data: &[u8]) -> (Self, PublicKey) {
		use rand::SeedableRng;
		let mut rng = rand::rngs::StdRng::from_seed(hash(data));
		let s = RsaPrivateKey::new(&mut rng, KEY_BITS).expect("failed to generate rsa private key");
		let p = PublicKey(RsaPublicKey::from(&s));
		(PrivateKey(s), p)
	}
	
	pub fn sign(&self, _data: &[u8]) -> [u8; SIGNATURE_BYTES] { //TODO
		[0; SIGNATURE_BYTES]
	}
	
	pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		self.0.decrypt(padding, data).expect("failed to decrypt data")
	}
}

impl PublicKey {
	pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
		let mut rng = rand::rngs::OsRng;
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		println!("encrypting: {:?}",data);
		self.0.encrypt(&mut rng, padding, data).expect("failed to encrypt")
	}
	
	pub fn verify(&self, _signature: [u8; SIGNATURE_BYTES], _data: &[u8]) -> bool { //TODO
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
	
	pub fn pop_bytes(buf: &mut Vec<u8>) -> Self {
		let mut r = [0; KEY_BITS / 8];
		for i in (0..r.len()).rev() {
			r[i] = buf.pop().unwrap();
		}
		deserialize(&r).expect("failed to deserialize rsa public key")
	}
	
	pub fn push_bytes(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&serialize(self));
	}
}
