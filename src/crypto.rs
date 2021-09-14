use crate::prelude::*;
use std::convert::TryInto;

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
pub struct SymmetricKey([u8; SYMMETRIC_KEY_BYTES]);

impl PrivateKey {
	pub fn min_decrypt_len(&self) -> usize {
		KEY_BYTES
	}
	
	pub fn from_phrase(data: &[u8]) -> (Self, PublicKey) {
		let mut rng = StdRng::from_seed(hash(data));
		let s = RsaPrivateKey::new(&mut rng, KEY_BITS).expect("failed to generate rsa private key");
		let p = PublicKey(RsaPublicKey::from(&s));
		(PrivateKey(s), p)
	}
	
	pub fn sign(&self, _data: &[u8], _to: &PublicKey) -> [u8; SIGNATURE_BYTES] { //TODO
		[0; SIGNATURE_BYTES]
	}
	
	pub fn decrypt(&self, mut data: Vec<u8>) -> Option<Vec<u8>> {
		println!("before decryption {}: {:?}",data.len(),data);
		let mut symm_key = [0; KEY_BYTES];
		if data.len() < symm_key.len() { return None; }
		for i in (0..symm_key.len()).rev() {
			symm_key[i] = data.pop().unwrap();
		}
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		if let Some(symm_key) = self.0.decrypt(padding, &symm_key).ok().and_then(|x| x[..].try_into().ok()) {
			let data = SymmetricKey(symm_key).decrypt(&data);
			println!("after decryption {}: {:?}",data.len(),data);
			Some(SymmetricKey(symm_key).decrypt(&data))
		} else {
			None
		}
	}
}

impl PublicKey {
	pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
		println!("before encryption {}: {:?}",data.len(),data);
		let mut rng = OsRng;
		let symm_key = SymmetricKey::new(&mut rng);
		let padding = PaddingScheme::new_pkcs1v15_encrypt();
		let mut data = symm_key.encrypt(data);
		let symm_key = self.0.encrypt(&mut rng, padding, &symm_key.0).expect("failed to encrypt");
		debug_assert!(symm_key.len() == KEY_BYTES);
		data.extend_from_slice(&symm_key);
		println!("after encryption {}: {:?}",data.len(),data);
		data
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
		let mut r = [0; KEY_BYTES];
		for i in (0..r.len()).rev() {
			r[i] = buf.pop().unwrap();
		}
		deserialize(&r).expect("failed to deserialize rsa public key")
	}
	
	pub fn push_bytes(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&serialize(self));
	}
}

impl SymmetricKey {
	pub fn new<R: Rng>(rng: &mut R) -> Self {
		let mut r = SymmetricKey(Default::default());
		rng.fill(&mut r.0);
		r
	}
	
	pub fn encrypt(mut self, data: &[u8]) -> Vec<u8> {
		println!("encrypting with symm_key: {:?}",self.0);
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
