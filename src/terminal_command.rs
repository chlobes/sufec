pub enum Command {
	Stop,
	WritePubKey(Option<String>),
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
				println!("commands are:\n-stop\n-write_pub_key <path>");
				None
			},
			"stop" => Some(Stop),
			"write_pub_key" => Some(WritePubKey(words.get(1).map(|x| x.to_string()))),
			x => {
				println!("unknown command: {}",x);
				None
			},
		}
	}
}
