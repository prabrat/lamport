use crate::crypto::prelude::*;

fn sign_message(msg: &[u8], sk: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {

    let msg_hash = Sha3_256::digest(msg); // hashing the msg inside 
    let mut signature: Vec<[u8; 16]> = Vec::new();

    for i in 0..256u32 { 
        let msg_byte = i / 8;
        let msg_bit = 7 - (i % 8);

        let bit_val = (msg_hash[msg_byte as usize] >> msg_bit) & 1; // Shifts curr bit to rightmost position and masks with 1 to isolate bit value
        let sk_index = (i * 2 + bit_val as u32) as usize; // 2i if bit val is 0 else 2i + 1

        signature.push(sk[sk_index]); // add to signature
    }

    signature 
    
}
