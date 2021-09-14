use crate::prelude::*;

#[derive(Clone,Serialize,Deserialize,Debug)]
pub struct Message {
	pub from: PublicKey,
	pub time: SystemTime,
	pub typ: MessageType,
	#[serde(with="serde_64_array")]
	pub signature: [u8; SIGNATURE_BYTES],
}

impl Message {
	pub fn hash(&self) -> [u8; HASH_BYTES] {
		let mut x = self.clone();
		x.signature = [0; SIGNATURE_BYTES];
		hash(&serialize(&x))
	}
}

#[derive(Clone,Serialize,Deserialize,Debug)]
pub enum MessageType {
	Message(String),
	Received([u8; HASH_BYTES]),
	//Seen([u8; HASH_BYTES]),
	//NewGroup(GroupId, String),
	Rename(String),
	RequestPeer(PublicKey, IpAddr),
}

mod serde_64_array {
	//TODO fix this hack that probably breaks when endianness is different
	use serde::{Serialize,Deserialize,Serializer,Deserializer};
	pub fn serialize<S: Serializer>(x: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
		let x: &[u64; 8] = unsafe { std::mem::transmute(x) };
		x.serialize(serializer)
	}
	
	pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
		let x = <[u64; 8]>::deserialize(deserializer)?;
		Ok(unsafe { std::mem::transmute(x) })
	}
}
