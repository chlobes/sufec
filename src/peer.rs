use crate::prelude::*;

#[derive(Copy,Clone,Serialize,Deserialize)]
pub struct Peer {
	pub key: PublicKey,
	pub ip: IpAddr,
	#[serde(serialize_with="se_instant",deserialize_with="de_instant")]
	pub last_online: Instant,
	#[serde(skip)]
	pub relative_key: u64,
}

impl Peer {
	pub fn punch(&self, socket: &UdpSocket) -> Result<()> {
		socket.send_to(&[], (self.ip, PORT))?;
		Ok(())
	}
}
