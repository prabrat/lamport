use crate::lamport::*;
use crate::crypto::prelude::*;

//just a thought maybe also change the functions to work with key files and signature files instead of doing io in main

//change function names in lamport to be like lamport_keyGen

pub fn keyGen(node: u32) -> ([u8;16], Vec<[u32; 16]>) {

}

// will output vec in format: {sigma_root, pk_0, pk_1, sigma_1, pk_10, pk_11, ... sigma_msg}
pub fn sign(msg: [u8]) -> Vec<[u8;16]> {

}

pub fn ver(signature: Vec<[u8;16]>, msg: [u8]) -> bool{

}