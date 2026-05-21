use crate::crypto::prelude::*;

fn generate_keys(seed: &[u8; 16]) -> (Vec<[u8; 16]>, Vec<[u8; 16]>) {
    let cipher = Aes128::new(GenericArray::from_slice(seed));
    let mut sk: Vec<[u8; 16]> = Vec::new();
    let mut pk: Vec<[u8; 16]> = Vec::new();

    for i in 0..256u32 {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&i.to_le_bytes());
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));

        // hash the sk block to get pk
        let hash = Sha3_256::digest(&block);
        let pk_key: [u8; 16] = hash[..16].try_into().unwrap();

        sk.push(block);
        pk.push(pk_key);
    }

    (sk, pk)
}

fn sign_message(msg: &[u8], sk: &Vec<[u8; 16]>) -> Vec<[u8; 16]> {

    let msg_hash: [u8; 16] = Sha3_256::digest(msg)[..16].try_into().unwrap(); // hashing the msg inside 
    let mut signature: Vec<[u8; 16]> = Vec::new();

    for i in 0..128 { 
        let byte = msg_hash[i / 8];
        let bit = ((byte >> (7 - (i % 8))) & 1) as usize;

        signature.push(sk[i+bit]); // add to signature
    }

    signature 
    
}

fn verify_signature(msg: &[u8], signature: &Vec<[u8; 16]>, public_key: &Vec<[u8; 16]>) -> bool {
    //compute message hash
    let msg_hash: [u8; 16] = Sha3_256::digest(msg)[..16].try_into().unwrap();
    //iterate through all bits
    for i in 0..128 {
        //find bit value (0 or 1)
        let byte = msg_hash[i / 8];
        let bit = ((byte >> (7 - (i % 8))) & 1) as usize;
        //find correlated hash in public key
        let pk_hash: [u8; 16] = public_key[2*i + bit];
        //get preiamge from signature and compute hash
        let preimage = signature[i];
        let computed_hash: [u8; 16] = Sha3_256::digest(preimage)[..16].try_into().unwrap();
        //compare the hashes, return false if they do not match
        if pk_hash != computed_hash{
            return false;
        }
    }
    true
}
