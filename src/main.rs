mod crypto;
mod lamport;
mod tree_impl;
use crate::tree_impl::*;
use std::io::{self, Write, BufRead};
use std::fs;

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        // clear screen
        print!("\x1B[2J\x1B[H");
        // draw UI
        println!("=== Lamport Signatures ===");
        println!("Commands: ");
        println!("KeyGen");
        println!("Sign <file path>");
        println!("Ver <file path>");
        println!("Quit\n");
        print!("> ");
        stdout.flush().unwrap();

        // read input
        let mut input = String::new();
        stdin.lock().read_line(&mut input).unwrap();
        let input = input.trim();
        let parts: Vec<&str> = input.splitn(2, ' ').collect();

        match parts[0] {
            "KeyGen" => {
                key_gen().unwrap();

                println!("Press enter to continue...");
                let mut buf = String::new();
                stdin.lock().read_line(&mut buf).unwrap();
            }

            "Sign" => {
                if parts.len() < 2 {
                    println!("Usage: Sign <file path>");
                    continue;
                }
                let file_path = parts[1];
                sign(file_path).unwrap();
            
                println!("Press enter to continue...");
                let mut buf = String::new();
                stdin.lock().read_line(&mut buf).unwrap();
            }

            "Ver" => {
                if parts.len() < 2 {
                    println!("Usage: Ver <file path>");
                    continue;
                }
                let file_path = parts[1];

                // read message file
                let msg = match fs::read(file_path) {
                    Ok(bytes) => bytes,
                    Err(e) => { println!("Error reading file: {}", e); continue; }
                };

                // read signature
                let sig_bytes = match fs::read("signature.bin") {
                    Ok(bytes) => bytes,
                    Err(e) => { println!("Error reading signature: {}", e); continue; }
                };

                // read public key
                let pk_bytes = match fs::read("public_key.bin") {
                    Ok(bytes) => bytes,
                    Err(e) => { println!("Error reading public key: {}", e); continue; }
                };

                // reconstruct as Vec<[u8; 16]>
                let signature: Vec<[u8; 16]> = sig_bytes
                    .chunks(16)
                    .map(|c| c.try_into().unwrap())
                    .collect();

                let pk: Vec<[u8; 16]> = pk_bytes
                    .chunks(16)
                    .map(|c| c.try_into().unwrap())
                    .collect();

                let valid = ver(&signature, &msg, &pk);

                if valid {
                    println!("Signature is VALID");
                } else {
                    println!("Signature is INVALID");
                }

                println!("Press enter to continue...");
                let mut buf = String::new();
                stdin.lock().read_line(&mut buf).unwrap();
            }

            "Quit" => break,

            _ => {
                println!("Unknown command");
            }
        }
    }
}