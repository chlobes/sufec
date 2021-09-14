#![feature(decl_macro)]

use prelude::*;
mod prelude;
mod packet;
mod message;
mod peer;
mod terminal_command;
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
	let socket = match UdpSocket::bind(("0.0.0.0", IN_PORT)).and_then(|x| x.set_nonblocking(true).map(|_| x)) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't bind to port {}: {}",IN_PORT,e);
			return;
		},
	};
	let passphrase = match std::fs::read_to_string(format!("{}/passphrase.txt",settings().folder)).or_else(|e| {
		println!("couldn't read passphrase: {}",e);
		create_passphrase()
	}) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't write passphrase to {}: {}",format!("{}/passphrase.txt",settings().folder),e);
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
	let mut sent_messages: HashMap<[u8; HASH_BYTES], Packet> = read_file(format!("{}/sent_messages.ron",settings().folder)).unwrap_or(HashMap::new());
	let mut packets: Vec<Packet> = read_file(format!("{}/packets.ron",settings().folder)).unwrap_or(Vec::new());
	packets.iter_mut().for_each(|p| p.relative_key = p.to.relative_to(&pub_key));
	let terminal = terminal::Terminal::start();
	let mut limiter = limiter::Limiter::from_tps(100.0);
	let mut last_punch = SystemTime::now() - Duration::from_secs(settings().punch_delay);
	let mut connected = Vec::new();
	let mut connected_map = HashMap::new();
	let mut buf = vec![0; MAX_PACKET_BYTES];
	'a: loop {
		while let Ok((len, addr)) = socket.recv_from(&mut buf) {
			if len != 0 {
				println!("packet len {}",len);
			}
			if let Ok(raw_packet) = deserialize::<RawPacket>(&buf) {
				println!("got raw packet {}",raw_packet.data.len());
				if let Some(packet) = raw_packet.decrypt(&priv_key) {
					println!("got packet {}",packet.data.len());
					if packet.to == pub_key {
						println!("got packet meant for us");
						if let Some(msg) = packet.decrypt(&priv_key) {
							if let MessageType::Message(text) = &msg.typ {
								for i in 0..friends.len() {
									if friends[i].key == msg.from {
										print!("msg from {}",friends[i].name);
										break;
									}
								}
								println!(": {}",text);
							}
							if let MessageType::Received(hash) = &msg.typ {
								if let Some(packet) = sent_messages.get(hash) {
									if packet.to == msg.from {
										sent_messages.remove(hash);
									}
								}
								//TODO: consider sending a garbage message to reduce trackability
							} else {
								let mut return_msg = Message {
									from: pub_key.clone(),
									time: SystemTime::now(),
									typ: MessageType::Received(msg.hash()),
									signature: [0; SIGNATURE_BYTES],
								};
								return_msg.signature = priv_key.sign(&return_msg.hash(), &msg.from);
								let packet = Packet::encrypt(msg.from.clone(), &return_msg);
								packets.push(packet);
							}
							messages.push(msg);
						}
					} else {
						packets.push(packet);
					}
				}
			} else if !connected_map.contains_key(&addr.ip()) {
				println!("recved connection from {}",addr.ip());
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
			buf = vec![0; MAX_PACKET_BYTES];
		}
		'b: for command in terminal.try_iter() {
			match command {
				Stop => break 'a,
				WritePubKey(path) => {
					let path = path.unwrap_or(format!("{}/pub_key.ron",settings().folder));
					match write_file(&pub_key, path.clone()) {
						Ok(()) => println!("wrote public key to {}",path),
						Err(e) => println!("failed to write public key to {}: {}",path,e),
					}
				},
				SendMsg(target, msg) => {
					for friend in friends.iter_mut() {
						if friend.name == target {
							let mut msg = Message {
								from: pub_key.clone(),
								time: SystemTime::now(),
								typ: MessageType::Message(msg),
								signature: [0; SIGNATURE_BYTES],
							};
							let hash = msg.hash();
							msg.signature = priv_key.sign(&hash, &friend.key);
							println!("sending: {:?}",msg);
							let packet = Packet::encrypt(friend.key.clone(), &msg);
							sent_messages.insert(hash, packet.clone());
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
					packet.last_sent = SystemTime::now();
					let mut i = connected.len() - 1;
					while connected[i].relative_key > packet.relative_key && i != 0 {
						i -= 1;
					}
					if connected[i].relative_key <= packet.relative_key {
						println!("sending packet to {}",connected[i].ip);
						if let Err(e) = connected[i].send(&socket, packet) {
							println!("error sending packet to {}: {}",connected[i].ip,e);
						}
					}
				}
			}
		}
		limiter.sleep();
	}
	if connected.len() > 0 { //dump all the packets we're holding onto
		packets.iter().for_each(|x| { let _ = connected[0].send(&socket, x); });
	}
	if let Err(e) = write_file(&peers, format!("{}/peers.ron",settings().folder)) {
		println!("error writing peers: {}",e);
	}
	if let Err(e) = write_file(&messages, format!("{}/messages.ron",settings().folder)) {
		println!("error writing messages: {}",e);
	}
	if let Err(e) = write_file(&sent_messages, format!("{}/sent_messages.ron",settings().folder)) {
		println!("error writing sent_messages: {}",e);
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
	punch_delay: 5,
	resend_delay: 2,
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
	ron::ser::to_writer_pretty(f, t, ron::ser::PrettyConfig::default().with_depth_limit(3))?;
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
