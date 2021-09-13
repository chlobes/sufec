use crate::prelude::*;

#[derive(Serialize,Deserialize,Debug)]
pub struct Message {
	pub from: PublicKey,
	//#[serde(serialize_with="se_instant",deserialize_with="de_instant")]
	pub time: SystemTime,
	pub typ: MessageType,
}

impl Message {
	pub fn hash(&self) -> [u8; HASH_SIZE] {
		hash(&serialize(self))
	}
}

#[derive(Serialize,Deserialize,Debug)]
pub enum MessageType {
	Message(String),
	Received([u8; HASH_SIZE]),
	//Seen([u8; HASH_SIZE]),
	//NewGroup(GroupId, String),
	Rename(String),
	RequestPeer(PublicKey, IpAddr),
}
