use crate::address::{AdrsType, set_layer_address, set_tree_address, set_type, set_kp_address};
use crate::configurations::{SpxConfig, SpxTweak, get_m1, get_m2, get_m3};
use crate::fors::{ForsSig, fors_sign, fors_pk_from_sig};
use crate::hypertree::{ht_pkgen, HtSig, ht_sign, ht_verify};
use crate::utils::{sec_rand,vec_to_u32,vec_to_u64};

#[derive(Clone)]
pub struct SpxSK {
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pk: SpxPK
}

impl SpxSK {
    pub fn size(&self) -> usize {
        self.sk_seed.len() + self.sk_prf.len() + self.pk.size()
    }
}

#[derive(Clone)]
pub struct SpxPK {
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>
}

impl SpxPK {
    pub fn size(&self) -> usize {
        self.pk_seed.len() + self.pk_root.len()
    }
}

/// Generates a SPHINCS+ secret and public key
pub fn spx_keygen<SC: SpxConfig + SpxTweak>() -> (SpxSK, SpxPK) {
    // Generate random byte vectors
    let sk_seed = sec_rand(SC::N);
    let sk_prf = sec_rand(SC::N);
    
    let pk_seed = sec_rand(SC::N);
    let pk_root = ht_pkgen::<SC>(&sk_seed, &pk_seed);
    
    let pk = SpxPK{pk_seed, pk_root};

    let pk_clone = pk.clone();
    let sk = SpxSK{sk_seed, sk_prf, pk: pk_clone};

    (sk, pk)
}

#[derive(Clone)]
pub struct SpxSig {
    randomness: Vec<u8>,
    sig_fors: ForsSig,
    sig_ht: HtSig
}

impl SpxSig {
    pub fn size(&self) -> usize {
        self.randomness.len() + self.sig_fors.size() + self.sig_ht.size()
    }
}

/// Takes a digest of size m and splits it into a message digest, tree_index and leaf_index
fn get_md_and_index<SC: SpxConfig>(digest: &[u8]) -> (Vec<u8>, u64, u32) {
    // Get indices
    let md_index = get_m1::<SC>() as usize;
    let idx_tree_index = md_index + get_m2::<SC>() as usize;
    let idx_leaf_index = idx_tree_index + get_m3::<SC>() as usize;
    
    let md = digest[0..md_index].to_vec();
    let tmp_idx_tree = digest[md_index..idx_tree_index].to_vec();
    let tmp_idx_leaf = digest[idx_tree_index..idx_leaf_index].to_vec();

    let idx_tree = vec_to_u64(tmp_idx_tree);
    let idx_leaf = vec_to_u32(tmp_idx_leaf);

    (md, idx_tree, idx_leaf)
}

/// Generates a SPHINCS+ signature
/// input:
/// message - The message to be signed has to be of length (?)
/// sk - The SPHINCS+ secret key to sign under
pub fn spx_sign<SC: SpxConfig + SpxTweak>(message: &[u8], sk: &SpxSK, random: bool) -> SpxSig {
    let adrs = &mut [0u8; 32];

    let opt = if random {
        vec![0u8; SC::N as usize]
    } else {
        sec_rand(SC::N)
    };
    
    let randomness = SC::prf_msg(&sk.sk_prf, &opt, message);

    // Compute message digest
    let digest = SC::h_msg(&randomness, &sk.pk.pk_seed, &sk.pk.pk_root, message);

    // Get message digest and indicies
    let (md,idx_tree,idx_leaf) = get_md_and_index::<SC>(&digest);

    // Calculate FORS sig
    set_layer_address(adrs, 0);
    set_tree_address(adrs, idx_tree);
    set_type(adrs, AdrsType::ForsTree);
    set_kp_address(adrs, idx_leaf);

    let sig_fors = fors_sign::<SC>(&md, &sk.sk_seed, &sk.pk.pk_seed, adrs);

    // Get fors public key
    let pk_fors = fors_pk_from_sig::<SC>(&sig_fors, &md, &sk.pk.pk_seed, adrs);

    // Sign fors public key with HT
    set_type(adrs, AdrsType::Tree);
    let sig_ht = ht_sign::<SC>(&pk_fors, &sk.sk_seed, &sk.pk.pk_seed, idx_tree, idx_leaf);

    //let sig = SpxSig{randomness, }
    let sig = SpxSig {randomness, sig_fors, sig_ht };
    sig
}

pub fn spx_verify<SC: SpxConfig + SpxTweak>(message: &[u8], sig: SpxSig, pk: &SpxPK) -> bool {
    let adrs = &mut [0u8; 32];
    let randomness = sig.randomness;
    let sig_fors = sig.sig_fors;
    let sig_ht = sig.sig_ht;

    // Random number
    let digest = SC::h_msg(&randomness, &pk.pk_seed, &pk.pk_root, message);
    
    // Get message digest and indicies
    let (md,idx_tree,idx_leaf) = get_md_and_index::<SC>(&digest);

    // Calculate FORS sig
    set_layer_address(adrs, 0);
    set_tree_address(adrs, idx_tree);
    set_type(adrs, AdrsType::ForsTree);
    set_kp_address(adrs, idx_leaf);
    
    // Get fors public key
    let pk_fors = fors_pk_from_sig::<SC>(&sig_fors, &md, &pk.pk_seed, adrs);

    set_type(adrs, AdrsType::Tree);
    ht_verify::<SC>(&pk_fors, &sig_ht, &pk.pk_seed, idx_tree, idx_leaf, &pk.pk_root)
}

#[cfg(test)]
mod tests {
    use crate::configurations;

    #[test]
    fn can_verify_sign() {
        let spx = crate::Spx::<configurations::Spx256fShakeR>::new(true);
        let (sk, pk) = spx.keygen();
        let message = b"";

        let sig = spx.sign(message, &sk);

        assert_eq!(spx.verify(message, sig, &pk), true)
    }

    #[test]
    fn cannot_verify_wrong_sig() {
        let spx = crate::Spx::<configurations::Spx128fShakeS>::new(true);
        let (sk, pk) = spx.keygen();
        let message = b"Okay, signaturen paa denne besked burde ikke kunne verifices, da vi aendrer signaturen, og derfor goer den ugyldig.".to_vec();

        let sig = spx.sign(&message, &sk);
        let mut sig1 = sig.clone();
        let mut sig2 = sig.clone();
        let mut sig3 = sig.clone();
        let mut sig4 = sig.clone();
        let mut sig5 = sig.clone();
        sig1.randomness[0] ^= 1;
        sig2.sig_fors.auth_trees[0].sk_value[0] ^= 1;
        sig3.sig_fors.auth_trees[0].auth_path[0][0] ^= 1;
        sig4.sig_ht.sigs[0].wots_sig[0][0] ^= 1;
        sig5.sig_ht.sigs[0].auth_path[0][0] ^= 1;

        assert_eq!(spx.verify(&message, sig1, &pk), false);
        assert_eq!(spx.verify(&message, sig2, &pk), false);
        assert_eq!(spx.verify(&message, sig3, &pk), false);
        assert_eq!(spx.verify(&message, sig4, &pk), false);
        assert_eq!(spx.verify(&message, sig5, &pk), false);
    }
}