use sha2::{Sha256, Digest};
use crate::configurations::{SpxConfig, get_m};
use crate::address::{Adrs, get_compress};
use hmac::{Hmac, Mac};

pub fn h_msg<SC: SpxConfig>(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> {
    let seed = Sha256::new()
        .chain_update(r)
        .chain_update(pk_seed)
        .chain_update(pk_root)
        .chain_update(m)
        .finalize().to_vec();
    mgf1_sha256(&seed, get_m::<SC>() as u64).unwrap()
}

pub fn mgf1_sha256(seed: &[u8], length: u64) -> Result<Vec<u8>, String> {
    let hlen = 256/8;
    if length > (2u64).pow(32)*hlen {
        return Err(String::from("mask too long"))
    }

    let mut t: Vec<u8> = Vec::with_capacity(length as usize);

    for i in 0..((length + hlen - 1) / hlen) { // No -1 as rust is exclusive
        let bytes = (i as u32).to_be_bytes();
        
        let mut hash = Sha256::new()
                                .chain_update(&seed)
                                .chain_update(bytes)
                                .finalize().to_vec();

        t.append(&mut hash);
    }

    Ok(t[..length as usize].to_vec())
}

// TODO
pub fn prf<SC: SpxConfig>(seed: &[u8], adrs: &Adrs) -> Vec<u8> {
    let comp_adrs = get_compress(adrs);
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(comp_adrs);
    hasher.finalize()[..SC::N as usize].to_vec()
}

pub fn prf_msg<SC: SpxConfig>(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(sk_prf).unwrap();
    mac.update(opt_rand);
    mac.update(m);
    mac.finalize().into_bytes()[..SC::N as usize].to_vec()
}