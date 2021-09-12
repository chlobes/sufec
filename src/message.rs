use crate::prelude::*;

#[derive(Serialize,Deserialize)]
pub struct Message {
	#[serde(serialize_with="se_instant",deserialize_with="de_instant")]
	pub time: Instant,
	pub typ: MessageType,
}

#[derive(Serialize,Deserialize)]
#[derive(Copy,Clone)]
pub struct GroupId(u64);

#[derive(Serialize,Deserialize)]
pub enum MessageType {
	Message(Vec<u8>),
	Received([u8; HASH_SIZE]),
	Seen([u8; HASH_SIZE]),
	NewGroup(GroupId, String),
	RequestPeer(PublicKey),
	Ping(PublicKey, IpAddr),
	Pong,
}
