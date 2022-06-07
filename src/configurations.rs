use crate::address::Adrs;
use crate::hash::tweakable::{tsha256, tshake256, tblake256};
use crate::hash::{sha256, shake256, blake256};

pub trait SpxTweak<SC: SpxConfig = Self> {
    fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8>;
    fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8>;
    fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8>;

    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8>;
    fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8>;
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8>;
}

pub trait SpxConfig {
    const N: u32;
    const H: u32;
    const D: u32;
    const A: u32;
    const K: u32;
    const W: u32;
}

pub fn get_h_prime<SC: SpxConfig>() -> u32 { SC::H / SC::D }
pub fn get_len1<SC: SpxConfig>() -> u32 { (8 * SC::N + get_lg_w::<SC>() - 1) / get_lg_w::<SC>() }
pub fn get_len2<SC: SpxConfig>() -> u32 { (((get_len1::<SC>() * (SC::W - 1)) as f64).log2() / get_lg_w::<SC>() as f64).floor() as u32 + 1 }
pub fn get_len<SC: SpxConfig>() -> u32 { get_len1::<SC>() + get_len2::<SC>() }
pub fn get_t<SC: SpxConfig>() -> u32 { 2u32.pow(SC::A) }
pub fn get_lg_w<SC: SpxConfig>() -> u32 { ((SC::W as f64).log2()).floor() as u32 }
pub fn get_m1<SC: SpxConfig>() -> u32 { (((SC::K * SC::A + 7) / 8) as f64).floor() as u32 }
pub fn get_m2<SC: SpxConfig>() -> u32 { (((SC::H - get_h_prime::<SC>() + 7) / 8) as f64).floor() as u32 }
pub fn get_m3<SC: SpxConfig>() -> u32 { (((get_h_prime::<SC>() + 7) / 8) as f64).floor() as u32 }
pub fn get_m<SC: SpxConfig>() -> u32 { get_m1::<SC>() + get_m2::<SC>() + get_m3::<SC>() }

pub struct Spx128sShakeR;
pub struct Spx128fShakeR;
pub struct Spx192sShakeR;
pub struct Spx192fShakeR;
pub struct Spx256sShakeR;
pub struct Spx256fShakeR;
pub struct Spx128sShakeS;
pub struct Spx128fShakeS;
pub struct Spx192sShakeS;
pub struct Spx192fShakeS;
pub struct Spx256sShakeS;
pub struct Spx256fShakeS;

pub struct Spx128sShaR;
pub struct Spx128fShaR;
pub struct Spx192sShaR;
pub struct Spx192fShaR;
pub struct Spx256sShaR;
pub struct Spx256fShaR;
pub struct Spx128sShaS;
pub struct Spx128fShaS;
pub struct Spx192sShaS;
pub struct Spx192fShaS;
pub struct Spx256sShaS;
pub struct Spx256fShaS;

pub struct Spx128sBlakeR;
pub struct Spx128fBlakeR;
pub struct Spx128sBlakeS;
pub struct Spx128fBlakeS;

macro_rules! impl_Spx128s {
    (for $($t:ty),+) => {
        $(impl SpxConfig for $t {
            const N: u32 = 16;
            const H: u32 = 63;
            const D: u32 = 7;
            const A: u32 = 12;
            const K: u32 = 14;
            const W: u32 = 16;
        })*
    }
}

macro_rules! impl_Spx128f {
    (for $($t:ty),+) => {
        $(impl SpxConfig for $t {
            const N: u32 = 16;
            const H: u32 = 66;
            const D: u32 = 22;
            const A: u32 = 6;
            const K: u32 = 33;
            const W: u32 = 16;
        })*
    }
}

macro_rules! impl_Spx192s {
    (for $($t:ty),+) => {
        $(impl SpxConfig for $t {
            const N: u32 = 24;
            const H: u32 = 63;
            const D: u32 = 7;
            const A: u32 = 14;
            const K: u32 = 17;
            const W: u32 = 16;
        })*
    }
}

macro_rules! impl_Spx192f {
    (for $($t:ty),+) => {
        $(impl SpxConfig for $t {
            const N: u32 = 24;
            const H: u32 = 66;
            const D: u32 = 22;
            const A: u32 = 8;
            const K: u32 = 33;
            const W: u32 = 16;
        })*
    }
}

macro_rules! impl_Spx256s {
    (for $($t:ty),+) => {
        $(impl SpxConfig for $t {
            const N: u32 = 32;
            const H: u32 = 64;
            const D: u32 = 8;
            const A: u32 = 14;
            const K: u32 = 22;
            const W: u32 = 16;
        })*
    }
}

macro_rules! impl_Spx256f {
    (for $($t:ty),+) => {
        $(impl SpxConfig for $t {
            const N: u32 = 32;
            const H: u32 = 68;
            const D: u32 = 17;
            const A: u32 = 9;
            const K: u32 = 35;
            const W: u32 = 16;
        })*
    }
}

macro_rules! impl_ShaR {
    (for $($t:ty),+) => {
        $(impl SpxTweak for $t {
            fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tsha256::f_robust::<Self>(pk_seed, adrs, message) }
            fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> { tsha256::h_robust::<Self>(pk_seed, adrs, concat_m) }
            fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tsha256::t_l_robust::<Self>(pk_seed, adrs, message) }
            fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> { sha256::h_msg::<Self>(r, pk_seed, pk_root, m) }
            fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8> { sha256::prf::<Self>(seed, adrs) }
            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> { sha256::prf_msg::<Self>(sk_prf, opt_rand, m) }
        })*
    }
}

macro_rules! impl_ShaS {
    (for $($t:ty),+) => {
        $(impl SpxTweak for $t {
            fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tsha256::f_simple::<Self>(pk_seed, adrs, message) }
            fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> { tsha256::h_simple::<Self>(pk_seed, adrs, concat_m) }
            fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tsha256::t_l_simple::<Self>(pk_seed, adrs, message) }
            fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> { sha256::h_msg::<Self>(r, pk_seed, pk_root, m) }
            fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8> { sha256::prf::<Self>(seed, adrs) }
            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> { sha256::prf_msg::<Self>(sk_prf, opt_rand, m) }
        })*
    }
}

macro_rules! impl_ShakeR {
    (for $($t:ty),+) => {
        $(impl SpxTweak for $t {
            fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tshake256::f_robust::<Self>(pk_seed, adrs, message) }
            fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> { tshake256::h_robust::<Self>(pk_seed, adrs, concat_m) }
            fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tshake256::t_l_robust::<Self>(pk_seed, adrs, message) }
            fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> { shake256::h_msg::<Self>(r, pk_seed, pk_root, m) }
            fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8> { shake256::prf::<Self>(seed, adrs) }
            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> { shake256::prf_msg::<Self>(sk_prf, opt_rand, m) }
        })*
    }
}

macro_rules! impl_ShakeS {
    (for $($t:ty),+) => {
        $(impl SpxTweak for $t {
            fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tshake256::f_simple::<Self>(pk_seed, adrs, message) }
            fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> { tshake256::h_simple::<Self>(pk_seed, adrs, concat_m) }
            fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tshake256::t_l_simple::<Self>(pk_seed, adrs, message) }
            fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> { shake256::h_msg::<Self>(r, pk_seed, pk_root, m) }
            fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8> { shake256::prf::<Self>(seed, adrs) }
            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> { shake256::prf_msg::<Self>(sk_prf, opt_rand, m) }
        })*
    }
}

macro_rules! impl_BlakeS {
    (for $($t:ty),+) => {
        $(impl SpxTweak for $t {
            fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tblake256::f_simple::<Self>(pk_seed, adrs, message) }
            fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> { tblake256::h_simple::<Self>(pk_seed, adrs, concat_m) }
            fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tblake256::t_l_simple::<Self>(pk_seed, adrs, message) }
            fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> { blake256::h_msg::<Self>(r, pk_seed, pk_root, m) }
            fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8> { blake256::prf::<Self>(seed, adrs) }
            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> { blake256::prf_msg::<Self>(sk_prf, opt_rand, m) }
        })*
    }
}

macro_rules! impl_BlakeR {
    (for $($t:ty),+) => {
        $(impl SpxTweak for $t {
            fn f(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tblake256::f_robust::<Self>(pk_seed, adrs, message) }
            fn h(pk_seed: &[u8], adrs: &Adrs, concat_m: &[u8]) -> Vec<u8> { tblake256::h_robust::<Self>(pk_seed, adrs, concat_m) }
            fn t_l(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> { tblake256::t_l_robust::<Self>(pk_seed, adrs, message) }
            fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> { blake256::h_msg::<Self>(r, pk_seed, pk_root, m) }
            fn prf(seed: &[u8], adrs: &Adrs) -> Vec<u8> { blake256::prf::<Self>(seed, adrs) }
            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> { blake256::prf_msg::<Self>(sk_prf, opt_rand, m) }
        })*
    }
}

impl_Spx128s!(for Spx128sShaR, Spx128sShaS, Spx128sShakeR, Spx128sShakeS, Spx128sBlakeR, Spx128sBlakeS);
impl_Spx128f!(for Spx128fShaR, Spx128fShaS, Spx128fShakeR, Spx128fShakeS, Spx128fBlakeR, Spx128fBlakeS);
impl_Spx192s!(for Spx192sShaR, Spx192sShaS, Spx192sShakeR, Spx192sShakeS);
impl_Spx192f!(for Spx192fShaR, Spx192fShaS, Spx192fShakeR, Spx192fShakeS);
impl_Spx256s!(for Spx256sShaR, Spx256sShaS, Spx256sShakeR, Spx256sShakeS);
impl_Spx256f!(for Spx256fShaR, Spx256fShaS, Spx256fShakeR, Spx256fShakeS);

impl_ShaR!(for Spx128sShaR, Spx128fShaR, Spx192sShaR, Spx192fShaR, Spx256sShaR, Spx256fShaR);
impl_ShaS!(for Spx128sShaS, Spx128fShaS, Spx192sShaS, Spx192fShaS, Spx256sShaS, Spx256fShaS);
impl_ShakeR!(for Spx128sShakeR, Spx128fShakeR, Spx192sShakeR, Spx192fShakeR, Spx256sShakeR, Spx256fShakeR);
impl_ShakeS!(for Spx128sShakeS, Spx128fShakeS, Spx192sShakeS, Spx192fShakeS, Spx256sShakeS, Spx256fShakeS);
impl_BlakeS!(for Spx128sBlakeS, Spx128fBlakeS);
impl_BlakeR!(for Spx128sBlakeR, Spx128fBlakeR);

