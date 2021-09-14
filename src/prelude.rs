//pub use std::mem;
pub use std::collections::HashMap;
pub use std::time::{SystemTime,Duration};
pub use std::net::{IpAddr,UdpSocket};
pub use std::io::{Read,Write};
pub use std::fs::{File,OpenOptions};
pub use std::convert::TryInto;
pub use std::error::Error;
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub use serde::{Serialize,Deserialize,de::DeserializeOwned};

pub use crate::settings;
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
