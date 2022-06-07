mod hash;
mod address;
mod wots;
mod configurations;
mod utils;
mod xmss;
mod hypertree;
mod fors;
mod sphincs_plus;

pub use configurations::{
    Spx128sShakeS, Spx128sShakeR, Spx128sShaS, Spx128sShaR, Spx128sBlakeS, Spx128sBlakeR,
    Spx128fShakeS, Spx128fShakeR, Spx128fShaS, Spx128fShaR, Spx128fBlakeS, Spx128fBlakeR,
    
    Spx192sShakeS, Spx192sShakeR, Spx192sShaS, Spx192sShaR,
    Spx192fShakeS, Spx192fShakeR, Spx192fShaS, Spx192fShaR,
    
    Spx256sShakeS, Spx256sShakeR, Spx256sShaS, Spx256sShaR,
    Spx256fShakeS, Spx256fShakeR, Spx256fShaS, Spx256fShaR,
};

pub use sphincs_plus::{SpxPK, SpxSK, SpxSig};
pub use configurations::{SpxTweak, SpxConfig};

use crate::sphincs_plus::{spx_keygen, spx_sign, spx_verify};
use std::{marker::PhantomData};

pub struct Spx<SC: SpxConfig + SpxTweak> {
    randomness: bool,
    p: PhantomData<SC>,
}

impl<SC: SpxConfig + SpxTweak> Spx<SC> {
    pub fn new(randomness: bool) -> Spx<SC> {
        Spx{
            randomness,
            p: PhantomData,
        }
    }

    pub fn keygen(&self) -> (SpxSK, SpxPK) {
        spx_keygen::<SC>()
    }

    pub fn sign(&self, message: &[u8], sk: &SpxSK) -> SpxSig {
        spx_sign::<SC>(message, sk, self.randomness)
    }

    pub fn verify(&self, message: &[u8], sig: SpxSig, pk: &SpxPK) -> bool {
        spx_verify::<SC>(message, sig, pk)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_key_size_128() {
        let spx = Spx::<Spx128fShaS>::new(true);
        let (sk, pk) = spx.keygen();

        assert_eq!(64, sk.size());
        assert_eq!(32, pk.size());
    }

    #[test]
    fn test_key_size_192() {
        let spx = Spx::<Spx192fShaS>::new(true);
        let (sk, pk) = spx.keygen();

        assert_eq!(96, sk.size());
        assert_eq!(48, pk.size());
    }

    #[test]
    fn test_key_size_256() {
        let spx = Spx::<Spx256fShaS>::new(true);
        let (sk, pk) = spx.keygen();

        assert_eq!(128, sk.size());
        assert_eq!(64, pk.size());
    }

    #[test]
    fn test_size_128s() {
        let spx = Spx::<Spx128sShaS>::new(true);
        let (sk, _) = spx.keygen();

        let sig = spx.sign(b"lulz", &sk);
        assert_eq!(7856, sig.size());
    }

    #[test]
    fn test_size_128f() {
        let spx = Spx::<Spx128fShaS>::new(true);
        let (sk, _) = spx.keygen();

        let sig = spx.sign(b"lulz", &sk);
        assert_eq!(17088, sig.size());
    }

    #[test]
    fn test_size_192s() {
        let spx = Spx::<Spx192sShaS>::new(true);
        let (sk, _) = spx.keygen();

        let sig = spx.sign(b"lulz", &sk);
        assert_eq!(16224, sig.size());
    }

    #[test]
    fn test_size_192f() {
        let spx = Spx::<Spx192fShaS>::new(true);
        let (sk, _) = spx.keygen();

        let sig = spx.sign(b"lulz", &sk);
        assert_eq!(35664, sig.size());
    }

    #[test]
    fn test_size_256s() {
        let spx = Spx::<Spx256sShaS>::new(true);
        let (sk, _) = spx.keygen();

        let sig = spx.sign(b"lulz", &sk);
        assert_eq!(29792, sig.size());
    }

    #[test]
    fn test_size_256f() {
        let spx = Spx::<Spx256fShaS>::new(true);
        let (sk, _) = spx.keygen();

        let sig = spx.sign(b"lulz", &sk);
        assert_eq!(49856, sig.size());
    }
}