#![feature(decl_macro)]

use prelude::*;
mod prelude;
#[allow(unused)]
mod packet;
mod message;
mod peer;
mod terminal_command;
#[allow(unused)]
mod hash;
mod crypto;
use terminal_command::*;

//const TARGET_PEERS: usize = 8;

fn main() {
	let args: Vec<String> = std::env::args().collect();
	if let Some(folder) = args.get(1) {
		unsafe {
			SETTINGS.folder = Box::leak(folder.clone().into_boxed_str());
		}
	} else if let Some(x) = home::home_dir() {
		if let Some(x) = x.to_str() {
			let folder = format!("{}/.sufec",x);
			unsafe {
				SETTINGS.folder = Box::leak(folder.into_boxed_str());
			}
		}
	}
	match std::fs::create_dir(settings().folder) {
		Ok(()) => {},
		Err(e) => if e.kind() != std::io::ErrorKind::AlreadyExists {
			println!("couldn't create data directory at {}: {}",settings().folder,e);
			return;
		}
	}
	match read_file(format!("{}/settings.ron",settings().folder)) {
		Ok(x) => unsafe { SETTINGS = x; },
		Err(e) => {
			println!("couldn't read settings: {}, using default",e);
			let _ = write_file(settings(), format!("{}/settings.ron",settings().folder));
		},
	}
	let socket = match UdpSocket::bind(("0.0.0.0", INPORT)).and_then(|x| x.set_nonblocking(true).map(|_| x)) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't bind to port {}: {}",INPORT,e);
			return;
		},
	};
	let passphrase = match std::fs::read_to_string(format!("{}/{}",settings().folder,"passphrase.txt")).or_else(|e| {
		println!("couldn't create passphrase: {}",e);
		create_passphrase()
	}) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't write passphrase to {}: {}",format!("{}/{}",settings().folder,"passphrase.txt"),e);
			return;
		},
	};
	let (priv_key, pub_key) = PrivateKey::from_phrase(passphrase.as_bytes());
	/*let peers = vec![ //create a default peer file to be given to other people for bootstrapping
		Peer {
			ip: std::net::Ipv4Addr::new(0,0,0,0).into(),
			key: pub_key.clone(),
			last_online: SystemTime::now(),
			relative_key: Default::default(),
		}
	];
	write_file(&peers, format!("{}/peers.ron",settings().folder)).unwrap();*/
	let mut peers: Vec<Peer> = match read_file(format!("{}/peers.ron",settings().folder)) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't read peers file: {}",e);
			return;
		},
	};
	//TODO: check whether the error was due to permissions or the file not existing
	let mut friends: Vec<Friend> = read_file(format!("{}/friends.ron",settings().folder)).unwrap_or(Vec::new());
	let mut messages: Vec<Message> = read_file(format!("{}/messages.ron",settings().folder)).unwrap_or(Vec::new());
	let mut packets: Vec<Packet> = read_file(format!("{}/packets.ron",settings().folder)).unwrap_or(Vec::new());
	packets.iter_mut().for_each(|p| p.relative_key = p.to.relative_to(&pub_key));
	let terminal = terminal::Terminal::start();
	let mut limiter = limiter::Limiter::from_tps(100.0);
	let mut last_punch = SystemTime::now() - Duration::from_secs(settings().punch_delay);
	let mut connected = Vec::new();
	let mut connected_map = HashMap::new();
	'a: loop {
		let mut buf = Vec::new();
		while let Ok((len, addr)) = socket.recv_from(&mut buf) {
			if len > 0 {
				println!("recved: {:?}",buf);
			}
			if let Some(packet) = Packet::from_bytes(&buf, &priv_key, &pub_key) {
				if packet.to == pub_key {
					if let Some(msg) = packet.decrypt(&priv_key) {
						//TODO: confirm that it's correctly signed
						println!("raw message: {:?}",msg);
						if let MessageType::Message(text) = &msg.typ {
							for i in 0..friends.len() {
								if friends[i].key == msg.from {
									print!("msg from {}",friends[i].name);
									break;
								}
							}
							println!(": {}",text);
						}
						if let MessageType::Received(_hash) = &msg.typ {
							//TODO
						} else {
							let return_msg = Message {
								from: pub_key.clone(),
								time: SystemTime::now(),
								typ: MessageType::Received(msg.hash()),
							};
							let packet = Packet::encrypt((&priv_key, &pub_key), msg.from.clone(), &return_msg);
							packets.push(packet);
						}
						messages.push(msg);
					}
				} else {
					unimplemented!()
				}
			} else if !connected_map.contains_key(&addr.ip()) {
				let mut i = 0;
				while i < peers.len() && peers[i].ip != addr.ip() {
					i += 1;
				}
				if i < peers.len() {
					peers[i].relative_key = peers[i].key.relative_to(&pub_key);
					connected_map.insert(addr.ip(), peers[i].clone());
					connected.push(peers[i].clone());
					connected.sort_unstable_by_key(|x| x.relative_key);
				}
			}
			buf = Vec::new();
		}
		'b: for command in terminal.try_iter() {
			match command {
				Stop => break 'a,
				WritePubKey(path) => {
					let path = path.unwrap_or(format!("{}/pub_key.txt",settings().folder));
					match std::fs::write(&path, serialize(&pub_key)) {
						Ok(()) => println!("wrote public key to {}",path),
						Err(e) => println!("failed to write public key to {}: {}",path,e),
					}
				},
				SendMsg(target, msg) => {
					for friend in friends.iter_mut() {
						if friend.name == target {
							let msg = Message {
								from: pub_key.clone(),
								time: SystemTime::now(),
								typ: MessageType::Message(msg),
							};
							let packet = Packet::encrypt((&priv_key, &pub_key), friend.key.clone(), &msg);
							packets.push(packet);
						}
						break 'b;
					}
					println!("no friend found with name: {}",target);
				}
			}
		}
		if last_punch.elapsed().unwrap() > Duration::from_secs(settings().punch_delay) {
			last_punch = SystemTime::now();
			for peer in peers.iter() {
				if let Err(e) = peer.punch(&socket) {
					println!("error punching {}: {}",peer.ip,e);
				}
			}
		}
		if connected.len() > 0 {
			for packet in packets.iter_mut() {
				if SystemTime::now() > packet.last_sent + Duration::from_secs(settings().resend_delay) {
					let mut i = connected.len() - 1;
					while connected[i].relative_key > packet.relative_key && i != 0 {
						i -= 1;
					}
					if connected[i].relative_key < packet.relative_key {
						match connected[i].send(&socket, &packet, &pub_key) {
							Ok(()) => packet.last_sent = SystemTime::now(),
							Err(e) => println!("error sending packet to {}: {}",connected[i].ip,e),
						}
					}
				}
			}
		}
		limiter.sleep();
	}
	if let Err(e) = write_file(&peers, format!("{}/peers.ron",settings().folder)) {
		println!("error writing peers: {}",e);
	}
	if let Err(e) = write_file(&messages, format!("{}/messages.ron",settings().folder)) {
		println!("error writing messages: {}",e);
	}
	if let Err(e) = write_file(&friends, format!("{}/friends.ron",settings().folder)) {
		println!("error writing friends: {}",e);
	}
}

fn settings_folder() -> &'static str {
	settings().folder
}
#[derive(Serialize,Deserialize)]
pub struct Settings {
	#[serde(skip,default="settings_folder")]
	pub folder: &'static str,
	pub punch_delay: u64,
	pub resend_delay: u64,
	pub username: String,
}
static mut SETTINGS: Settings = Settings {
	folder: ".sufec",
	punch_delay: 30,
	resend_delay: 10,
	username: String::new(),
};
pub fn settings() -> &'static Settings {
	unsafe { &SETTINGS }
}

fn read_file<T: DeserializeOwned>(path: String) -> Result<T> {
	let f = File::open(path)?;
	Ok(ron::de::from_reader(f)?)
}

fn write_file<T: Serialize>(t: &T, path: String) -> Result<()> {
	let f = File::create(path)?;
	ron::ser::to_writer_pretty(f, t, Default::default())?;
	Ok(())
}

fn create_passphrase() -> Result<String> {
	let path = format!("{}/passphrase.txt",settings().folder);
	use std::io::stdin;
	let mut readable = None;
	while readable.is_none() {
		println!("generate human readable passphrase? [y/n]");
		let mut x = String::new();
		stdin().read_line(&mut x)?;
		match x.chars().next() {
			Some('y') => readable = Some(true),
			Some('n') => readable = Some(false),
			_ => {},
		}
	}
	let mut r = String::new();
	if readable.unwrap() {
		let words: Vec<_> = include_str!("wordlist.txt").lines().collect();
		for _ in 0..12 {
			let i: usize = rand::random();
			r.push_str(&words[i % words.len()]);
			r.push(' ');
		}
		r.pop();
	} else {
		for _ in 0..32 {
			r.push(rand::random());
		}
	};
	let mut f = File::create(&path)?;
	f.write_all(r.as_bytes())?;
	println!("wrote passphrase to {}",path);
	Ok(r)
}
