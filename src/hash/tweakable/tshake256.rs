use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use crate::address::Adrs;
use crate::configurations::SpxConfig;

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
    let mut hasher = Shake256::default();
    let m_xor = m_xof(message, pk_seed, adrs);
    hasher.update(pk_seed);
    hasher.update(adrs);
    hasher.update(&m_xor);
    let mut reader = hasher.finalize_xof();
    let mut res = vec![0; SC::N as usize];
    reader.read(&mut res);
    res
}

pub fn t_l_simple<SC: SpxConfig>(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(pk_seed);
    hasher.update(adrs);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut res = vec![0; SC::N as usize];
    reader.read(&mut res);
    res
}

fn m_xof(message: &[u8], pk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
    let m_byte_length = message.len();
    let mut shake = vec![0; m_byte_length];

    let mut hasher = Shake256::default();
    hasher.update(pk_seed);
    hasher.update(adrs);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut shake);

    message.iter()
            .zip(shake.iter())
            .map(|(&x1, &x2)| x1 ^ x2).collect()
}