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
