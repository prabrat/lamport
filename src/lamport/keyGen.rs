use crate::crypto::prelude::*;

/* 
    Using AES-128 as a deterministic PRF to generate Public/Secret key paid from a seed 
    Takes in a seed and number of keys to generate, and outputs a vector of (sk, pk) pairs

    Block code for AES-256: 
        let mut block = GenericArray::clone_from_slice(&[0u8; 16]); 
        block[0] = i as u8; // Use the index as part of the input 
*/
fn generate_keys(seed: &[u8; 16], n: usize) -> Vec<(String, String)> {
    let secret = Aes128::new(GenericArray::from_slice(seed)); // creates cipher using seed 
    let mut keys = Vec::new();
    for i in 0..n {
        let mut block = GenericArray::clone_from_slice(&[0u8; 16]); 
        secret.encrypt_block(&mut block);

        let sk_hash = Sha3_256::digest(&block);
        let pk_hash = Sha3_256::digest(&sk_hash);
        let pk = hex::encode(sk_hash);
        let sk = hex::encode(pk_hash);
        keys.push((sk, pk));
    }
    keys
}

