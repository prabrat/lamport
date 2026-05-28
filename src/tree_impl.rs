use crate::crypto::prelude::*;
use crate::lamport::*;
use std::fs;
use rand::random;

pub fn key_gen() -> Result<(), Box<dyn std::error::Error>> {
    let seed: [u8; 16] = random();
    fs::write("secret_key.bin", &seed)?;

    let cipher = Aes128::new(GenericArray::from_slice(&seed));
    let mut seed_root = [0u8; 16];
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut seed_root));

    let (_, pk) = lamport_generate_keys(&seed_root);
    let pk_bytes: Vec<u8> = pk.iter().flatten().copied().collect();
    fs::write("public_key.bin", &pk_bytes)?;

    println!("Keys written to secret_key.bin and public_key.bin");
    Ok(())
}

pub fn sign(msg_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let msg = fs::read(msg_path)?;
    let sk_bytes = fs::read("secret_key.bin")?;

    let msg_hash: [u8; 16] = Sha3_256::digest(&msg)[..16].try_into()?;

    let cipher = Aes128::new(GenericArray::from_slice(&sk_bytes));

    let mut seed_root = [0u8; 16];
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut seed_root));

    // `position` is the index of the current node within its level (0-based)
    let mut position: u128 = 0;
    let mut signature: Vec<u8> = Vec::new();

    for i in 0..128usize {
        let byte = msg_hash[i / 8];
        let bit = ((byte >> (7 - (i % 8))) & 1) as u128;

        let left_child_index = position * 2;

        let (sk_root, _) = lamport_generate_keys(&seed_root);

        // Use u128 -> [u8; 16] directly, fits perfectly
        let mut seed_0 = [0u8; 16];
        seed_0.copy_from_slice(&left_child_index.to_le_bytes());
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut seed_0));
        let (_, pk_0) = lamport_generate_keys(&seed_0);

        let mut seed_1 = [0u8; 16];
        seed_1.copy_from_slice(&(left_child_index + 1).to_le_bytes());
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut seed_1));
        let (_, pk_1) = lamport_generate_keys(&seed_1);

        let pk: Vec<u8> = pk_0.iter().chain(pk_1.iter())
            .flatten()
            .copied()
            .collect();
        let sigma = lamport_sign_message(&pk, &sk_root);

        signature.extend(sigma.iter().flatten().copied());
        signature.extend(pk_0.iter().flatten().copied());
        signature.extend(pk_1.iter().flatten().copied());

        position = left_child_index + bit;
        if bit == 1 {
            seed_root = seed_1;
        } else {
            seed_root = seed_0;
        }
    }

    // Sign the actual message with the final leaf key
    let (sk_root, _) = lamport_generate_keys(&seed_root);
    let sigma_msg = lamport_sign_message(&msg, &sk_root);
    signature.extend(sigma_msg.iter().flatten().copied());

    fs::write("signature.bin", &signature)?;
    Ok(())
}


/* 
    signature layout: [sigma_0, pk_left_0, pk_right_0, sigma_1, pk_left_1, pk_right_1, ..., sigma_127, pk_left_127, pk_right_127, sigma_msg]
    sigma: 128 elems, contains signature of pk_left || pk_right 
    ph_left: 256 elems 
    pk_right: 256 elems
*/
pub fn ver(signature: &[[u8; 16]], msg: &[u8], root_pk: &Vec<[u8; 16]>) -> bool {
    let msg_hash: [u8; 16] = Sha3_256::digest(msg)[..16].try_into().unwrap();

    let mut parent_pk: Vec<[u8; 16]> = root_pk.clone();
    let mut idx = 0;

    for i in 0..128usize {
        let byte = msg_hash[i / 8];
        let bit = ((byte >> (7 - (i % 8))) & 1) as usize;

        let sigma    = signature[idx       .. idx + 128].to_vec();
        let pk_left  = signature[idx + 128 .. idx + 384].to_vec(); // 128 + 256 = 384
        let pk_right = signature[idx + 384 .. idx + 640].to_vec(); // 384 + 256 = 640
        idx += 640;

        // parent_pk should verify sigma against the two concatenated children 
        let child_pks: Vec<u8> = pk_left.iter().chain(pk_right.iter())
            .flatten().copied().collect();

        if !lamport_verify_signature(&child_pks, &sigma, &parent_pk) {
            return false;
        }

        parent_pk = if bit == 0 { pk_left } else { pk_right };
    }

    // Leaf key signs the actual message.
    let sigma_msg = signature[idx .. idx + 128].to_vec();
    lamport_verify_signature(msg, &sigma_msg, &parent_pk)
}