use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::configurations::{SpxConfig, get_m};
use crate::address::Adrs;

pub fn h_msg<SC: SpxConfig>(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(r);
    hasher.update(pk_seed);
    hasher.update(pk_root);
    hasher.update(m);
    let mut reader = hasher.finalize_xof();
    let mut res = vec![0; get_m::<SC>() as usize];
    reader.read(&mut res);
    res
}

pub fn prf<SC: SpxConfig>(seed: &[u8], adrs: &Adrs) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(adrs);
    let mut reader = hasher.finalize_xof();
    let mut res = vec![0; SC::N as usize];
    reader.read(&mut res);
    res
}

pub fn prf_msg<SC: SpxConfig>(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(sk_prf);
    hasher.update(opt_rand);
    hasher.update(m);
    let mut reader = hasher.finalize_xof();
    let mut res = vec![0; SC::N as usize];
    reader.read(&mut res);
    res
    
}