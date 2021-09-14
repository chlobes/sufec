//TODO: this could be more efficient if we switched to u64. it would be further breaking from standard sha tho


pub const HASH_BYTES: usize = 32;

const BLOCK_BYTES: usize = 64;
const INITIAL_STATE: [u32; 8] = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
const HASH_CONSTANTS: [u32; 64] = [
	1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221,
	3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580,
	3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
	2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895,
	666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
	2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
	430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779,
	1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298,
];

pub fn hash(data: &[u8]) -> [u8; HASH_BYTES] {
	let mut state = INITIAL_STATE;
	let iter = data.chunks_exact(BLOCK_BYTES);
	let remainder = iter.remainder();
	for chunk in iter {
		use std::convert::TryInto;
		process_chunk(&mut state, chunk.try_into().unwrap());
	}
	/*
	//this can be done for exact adherence to sha2, but just xoring the length is faster and simpler
	let mut last: Vec<_> = iter.remainder().iter().cloned().collect();
	last.push(128);
	while (last.len() + BLOCK_WORDS) % BLOCK_WORDS != (BLOCK_WORDS - std::mem::size_of::<u64>()) {
		last.push(0);
	}
	last.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());
	for chunk in last.chunks_exact(BLOCK_WORDS) {
		process_chunk(&mut state, &last);
	}
	*/
	let mut last = [0; BLOCK_BYTES];
	for i in 0..remainder.len() {
		last[i] = remainder[i];
	}
	for i in 0..8 {
		last[BLOCK_BYTES+i-8] ^= (data.len() as u64).to_be_bytes()[i];
	}
	process_chunk(&mut state, last);
	let mut result = [0; HASH_BYTES];
	for i in 0..8 {
		for j in 0..4 {
			result[i*4+j] = state[i].to_be_bytes()[j];
		}
	}
	result
}

fn process_chunk(state: &mut [u32; 8], chunk: [u8; BLOCK_BYTES]) {
	let mut w = [0; 64];
	for i in 0..16 {
		w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
	}
	for i in 16..64 {
		let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
		let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
		w[i] = s0.wrapping_add(s1).wrapping_add(w[i-16]).wrapping_add(w[i-7]);
	}
	let mut s = *state;
	for i in 0..64 {
		let s1 = s[4].rotate_right(6) ^ s[4].rotate_right(11) ^ s[4].rotate_right(25);
		let ch = (s[4] & s[5]) ^ ((!s[4]) & s[6]);
		let s0 = s[0].rotate_right(2) ^ s[0].rotate_right(13) ^ s[0].rotate_right(22);
		let maj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
		let tmp = s[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(HASH_CONSTANTS[i]).wrapping_add(w[i]);
		s[7] = s[6];
		s[6] = s[5];
		s[5] = s[4];
		s[4] = s[3].wrapping_add(tmp);
		s[3] = s[2];
		s[2] = s[1];
		s[1] = s[0];
		s[0] = tmp.wrapping_add(s0).wrapping_add(maj);
	}
	for i in 0..8 {
		state[i] = state[i].wrapping_add(s[i]);
	}
}
