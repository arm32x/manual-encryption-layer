extern crate ctrlc;
extern crate clipboard;
extern crate data_encoding;
extern crate rand;
extern crate x448;

use crypto::aessafe::AesSafe256Decryptor;
use crypto::aessafe::AesSafe256Encryptor;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::BlockDecryptor;
use crypto::symmetriccipher::BlockEncryptor;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use data_encoding::BASE64;
use rand::rngs::OsRng;
use std::io;
use std::process;
use x448::Secret;
use x448::PublicKey;

fn main() {
	let _ = ctrlc::set_handler(move || {
		process::exit(0);
	});

	let mut clip: ClipboardContext = ClipboardProvider::new().unwrap();

	let our_secret = Secret::new(&mut OsRng);
	let our_public_key = PublicKey::from(&our_secret);

	let our_public_key_base64 = BASE64.encode(our_public_key.as_bytes());

	println!("Your public key is displayed below and has been copied to your clipboard.");
	println!("Share it with the intended recipient of your encrypted messages.");
	println!("{}", our_public_key_base64);
	clip.set_contents(our_public_key_base64).unwrap();

	let mut their_public_key_base64 = String::new();
	let their_public_key: PublicKey;
	loop {
		println!("\nPaste the recipient's public key here to begin communication.");
		match io::stdin().read_line(&mut their_public_key_base64) {
			Ok(_s) => {
				match BASE64.decode(their_public_key_base64.trim_end().as_bytes()) {
					Ok(bytes) => {
						match PublicKey::from_bytes(bytes.as_slice()) {
							Some(key) => {
								their_public_key = key;
								break;
							}
							None => {
								// TODO:  Display a more useful error message.
								println!("The public key you entered appears to be invalid.");
							}
						}
					}
					Err(error) => {
						println!("The public key you entered appears to be invalid.");
						println!("Base64 {} error at position {}.", error.kind, error.position);
					}
				}
			}
			Err(message) => {
				println!("There was an error reading your input.  Please try again.");
				println!("{}", message);
			}
		}
		their_public_key_base64.clear();
	}

	let mut hasher = Sha256::new();

	let shared_secret = our_secret.to_diffie_hellman(&their_public_key).unwrap();
	hasher.input(shared_secret.as_bytes());

	let mut key = vec![0; 32];
	hasher.result(&mut key);

	let decryptor = AesSafe256Decryptor::new(&key[..]);
	let encryptor = AesSafe256Encryptor::new(&key[..]);

	println!("\nEncryption has been established.");
	println!("Write messages here to encrypt them.  Encrypted messages are copied to the clipboard.");
	println!("Paste encrypted messages here to decrypt them.");
	println!("Use CTRL-C to quit.\n");

	let mut input = String::new();
	loop {
		match io::stdin().read_line(&mut input) {
			Ok(_) => {
				if input.trim().starts_with("enc-") {
					match BASE64.decode(input.trim()[4..].as_bytes()) {
						Ok(encrypted_bytes) => {
							let blocks_iter = encrypted_bytes.chunks_exact(16);
							if blocks_iter.remainder().len() == 0 {
								let blocks: Vec<&[u8]> = blocks_iter.collect();

								let mut decrypted_bytes: Vec<u8> = Vec::new();
								let mut decrypted_block = vec![0; 16];
								for block in blocks {
									decryptor.decrypt_block(block, &mut decrypted_block);
									decrypted_bytes.extend_from_slice(&decrypted_block);
								}

								match String::from_utf8(decrypted_bytes) {
									Ok(output) => {
										println!("{}\n", output.trim());
									}
									Err(error) => {
										println!("The encrypted message you entered is invalid:  {}.", error);
										println!("This probably means that the public keys were not exchanged correctly.")
									}
								}
							} else {
								println!("The encrypted message you entered is invalid.");
								println!("It does not contain an integer number of blocks.")
							}
						}
						Err(error) => {
							println!("The encrypted message you entered is invalid.");
							println!("Base64 {} error at position {}.", error.kind, error.position);
						}
					}
				} else {
					let blocks_iter = input.trim().as_bytes().chunks_exact(16);

					let mut remainder: Vec<u8> = blocks_iter.remainder().to_vec();
					let mut blocks: Vec<&[u8]> = blocks_iter.collect();
					if remainder.len() > 0 {
						while remainder.len() < 16 {
							remainder.push(b' ');
						}
						blocks.push(&remainder[..]);
					}

					let mut encrypted_bytes: Vec<u8> = Vec::new();
					let mut encrypted_block = vec![0; 16];
					for block in blocks {
						encryptor.encrypt_block(block, &mut encrypted_block);
						encrypted_bytes.extend_from_slice(&encrypted_block);
					}

					let output = format!("enc-{}", BASE64.encode(&encrypted_bytes));
					println!("{}\n", output);
					clip.set_contents(output).unwrap();
				}
			}
			Err(error) => {
				println!("There was an error reading your input.  Please try again.");
				println!("{}", error);
			}
		}
		input.clear();
	}
}
