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

const TARGET_PEERS: usize = 8;

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
	match read_file(format!("{}/{}",settings().folder,"settings.toml")) {
		Ok(x) => unsafe { SETTINGS = x; },
		Err(e) => println!("couldn't read settings: {}, using default",e),
	}
	//let mut write_settings = false;
	let socket = match UdpSocket::bind(("0.0.0.0", PORT)).and_then(|x| x.set_nonblocking(true).map(|_| x)) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't bind to port {}: {}",PORT,e);
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
	let peers: HashMap<IpAddr, Peer> = peers.into_iter().map(|x| (x.ip, x)).collect();
	write_peers(&peers).unwrap();
	let peers: Vec<Peer> = match read_file(format!("{}/{}",settings().folder,"peers.toml")) {
		Ok(x) => x,
		Err(e) => {
			println!("couldn't read peers file: {}",e);
			return;
		},
	};
	let mut peers: HashMap<IpAddr, Peer> = peers.into_iter().map(|x| (x.ip, x)).collect();
	//TODO: check whether the error was due to permissions or the file not existing
	let _messages: Vec<RecvedMsg> = read_file(format!("{}/{}",settings().folder,"messages.toml")).unwrap_or(Vec::new());
	let terminal = terminal::Terminal::start();
	let mut limiter = limiter::Limiter::from_tps(100.0);
	let mut last_punch = Instant::now() - Duration::from_secs(settings().punch_delay as u64 + 1);
	let mut buf = Vec::new();
	let mut connected = Vec::new();
	let mut connected_map = HashMap::new();
	'a: loop {
		while let Ok((len, addr)) = socket.recv_from(&mut buf) {
			if len > 0 {
				println!("recved: {:?}",buf);
				if let Some(_packet) = Packet::from_bytes(&buf, &priv_key) {
					unimplemented!()
				} else if !connected_map.contains_key(&addr.ip()) {
					if let Some(peer) = peers.get_mut(&addr.ip()) {
						peer.relative_key = peer.key.relative_to(pub_key);
						connected_map.insert(addr.ip(), peer.clone());
						connected.push(peer.clone());
						connected.sort_unstable_by_key(|x| x.relative_key);
					}
				}
			}
			buf = Vec::new();
		}
		for command in terminal.try_iter() {
			match command {
				Stop => break 'a,
				WritePubKey(path) => {
					let path = path.unwrap_or(format!("{}/{}",settings().folder,"pub_key.txt"));
					match std::fs::write(&path, serialize(&pub_key)) {
						Ok(()) => println!("wrote public key to {}",path),
						Err(e) => println!("failed to write public key to {}: {}",path,e),
					}
				},
			}
		}
		if Instant::now() - last_punch < Duration::from_secs(settings().punch_delay as u64) {
			last_punch = Instant::now();
			for peer in peers.values() {
				if let Err(e) = peer.punch(&socket) {
					println!("error punching {}: {}",peer.ip,e);
				}
			}
			if connected.len() < TARGET_PEERS {
				unimplemented!()
			}
		}
		limiter.sleep();
	}
	if let Err(e) = write_peers(&peers) {
		println!("error writing peers: {}",e);
	}
}

fn settings_folder() -> &'static str {
	settings().folder
}
#[derive(Deserialize)]
pub struct Settings {
	#[serde(skip,default="settings_folder")]
	pub folder: &'static str,
	pub punch_delay: u16,
}
static mut SETTINGS: Settings = Settings {
	folder: ".sufec",
	punch_delay: 30,
};
pub fn settings() -> &'static Settings {
	unsafe { &SETTINGS }
}

fn read_file<T: DeserializeOwned>(path: String) -> Result<T> {
	let mut f = File::open(path)?;
	let mut r = Vec::new();
	f.read_to_end(&mut r)?;
	Ok(toml::from_slice(&r)?)
}

fn create_passphrase() -> Result<String> {
	let path = format!("{}/{}",settings().folder,"passphrase.txt");
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

fn write_peers(peers: &HashMap<IpAddr, Peer>) -> Result<()> {
	let mut ops = OpenOptions::new();
	let ops = ops.create(true).write(true);
	let mut f = ops.open(format!("{}/{}",settings().folder,"peers.toml"))?;
	f.write_all(toml::to_string_pretty(&peers)?.as_bytes())?;
	Ok(())
}

#[derive(Serialize,Deserialize)]
struct RecvedMsg {
	#[serde(serialize_with="se_instant",deserialize_with="de_instant")]
	time: Instant,
	from: PublicKey,
	target: GroupId,
	content: String,
}
