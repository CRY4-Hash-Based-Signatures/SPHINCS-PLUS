use sha2::{Sha256, Digest};
use crate::address::{Adrs, get_compress};
use crate::configurations::SpxConfig;
use crate::utils::to_byte;
use crate::hash::sha256::mgf1_sha256;

pub fn f_robust<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    t_l_robust::<SC>(pk_seed, adrs, message)
}

pub fn f_simple<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    t_l_simple::<SC>(pk_seed, adrs, message)
}

pub fn h_robust<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> {
    t_l_robust::<SC>(pk_seed, adrs, concat_m)
}

pub fn h_simple<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> {
    t_l_simple::<SC>(pk_seed, adrs, concat_m)
}

pub fn t_l_robust<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let boats = to_byte(0, 64 - SC::N as u32);
    let cmpr_adrs = get_compress(adrs);
    let m_xor = m_xof(message, &pk_seed, &cmpr_adrs);
    hasher.update(pk_seed);
    hasher.update(boats);
    hasher.update(cmpr_adrs);
    hasher.update(m_xor);
    hasher.finalize()[..SC::N as usize].to_vec()
}

pub fn t_l_simple<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let boats = to_byte(0, 64 - SC::N as u32);
    let cmpr_adrs = get_compress(adrs);
    hasher.update(pk_seed);
    hasher.update(boats);
    hasher.update(cmpr_adrs);
    hasher.update(message);
    hasher.finalize()[..SC::N as usize].to_vec()
}

fn m_xof(message: &[u8], pk_seed: &[u8], adrs_cmpr: &[u8]) -> Vec<u8> {
    let m_byte_length = message.len();
    let concat = [pk_seed, adrs_cmpr].concat();
    message.iter()
            .zip(mgf1_sha256(&concat, m_byte_length as u64).unwrap().iter())
            .map(|(&x1, &x2)| x1 ^ x2).collect()
}