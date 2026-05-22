mod crypto;
mod lamport;
use crate::lamport::*; 
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
                // generate random seed
                let mut seed = [0u8; 16];
                for (i, byte) in seed.iter_mut().enumerate() {
                    *byte = i as u8; // replace with a real RNG in production
                }

                let (sk, pk) = generate_keys(&seed);

                // flatten vecs to bytes and write to files
                let sk_bytes: Vec<u8> = sk.iter().flatten().copied().collect();
                let pk_bytes: Vec<u8> = pk.iter().flatten().copied().collect();

                fs::write("secret_key.bin", &sk_bytes).unwrap();
                fs::write("public_key.bin", &pk_bytes).unwrap();

                println!("Keys written to secret_key.bin and public_key.bin");
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

                // read message file
                let msg = match fs::read(file_path) {
                    Ok(bytes) => bytes,
                    Err(e) => { println!("Error reading file: {}", e); continue; }
                };

                // read secret key
                let sk_bytes = match fs::read("secret_key.bin") {
                    Ok(bytes) => bytes,
                    Err(e) => { println!("Error reading secret key: {}", e); continue; }
                };

                // reconstruct sk as Vec<[u8; 16]>
                let sk: Vec<[u8; 16]> = sk_bytes
                    .chunks(16)
                    .map(|c| c.try_into().unwrap())
                    .collect();

                let signature = sign_message(&msg, &sk);

                // flatten and write signature
                let sig_bytes: Vec<u8> = signature.iter().flatten().copied().collect();
                fs::write("signature.bin", &sig_bytes).unwrap();

                println!("Signature written to signature.bin");
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

                let valid = verify_signature(&msg, &signature, &pk);

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