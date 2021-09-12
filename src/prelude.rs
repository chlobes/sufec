pub use std::mem;
pub use std::collections::HashMap;
pub use std::time::{Instant,Duration};
pub use std::net::{IpAddr,UdpSocket};
pub use std::io::{Read,Write};
pub use std::fs::{File,OpenOptions};
pub use std::error::Error;
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub use serde::{Serialize,Deserialize,de::DeserializeOwned};

pub use crate::message::*;
pub use crate::packet::*;
pub use crate::peer::*;
pub use crate::crypto::*;

pub macro l() {
	&concat!(file!(), " ", line!())
}

pub fn serialize<T: Serialize>(x: &T) -> Vec<u8> {
	rmp_serde::to_vec(x).expect(l!())
}
pub fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
	Ok(rmp_serde::from_read_ref(data)?)
}
use serde::{Serializer,Deserializer};
pub fn se_instant<S: Serializer>(instant: &Instant, s: S) -> std::result::Result<S::Ok, S::Error> {
	instant.elapsed().serialize(s)
}
pub fn de_instant<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Instant, D::Error> {
	let duration = Duration::deserialize(d)?;
	Instant::now().checked_sub(duration).ok_or_else(|| serde::de::Error::custom(format!("failed to deserialize instant from duration: {:?}",duration)))
}
