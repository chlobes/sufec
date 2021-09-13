pub enum Command {
	Stop,
	WritePubKey(Option<String>),
	SendMsg(String, String),
	
}
pub use Command::*;

impl terminal::Parse for Command {
	fn parse(s: &String) -> Option<Self> {
		let words = s.split_whitespace().map(|w| w.trim()).collect::<Vec<_>>();
		if words.is_empty() {
			return None;
		}
		match words[0].to_lowercase().as_str() {
			"help" => {
				println!("commands are:\n-stop\n-write_pub_key <path>\n-send <name> <message>");
				None
			},
			"stop" => Some(Stop),
			"write_pub_key" => Some(WritePubKey(words.get(1).map(|x| x.to_string()))),
			"send" => if let Some(name) = words.get(1) {
				let mut r = String::new();
				for i in 2..words.len() {
					r += words[i];
					r += " ";
				}
				r.pop();
				Some(SendMsg(name.to_string(), r))
			} else {
				println!("usage: send <name> <message>");
				None
			}
			x => {
				println!("unknown command: {}",x);
				None
			},
		}
	}
}
