use crate::address::{set_layer_address, set_tree_address};
use crate::configurations::{SpxConfig, SpxTweak, get_h_prime};
use crate::xmss::{xmss_pkgen, xmss_sign, xmss_pk_from_sig, XmssSig};

#[derive(Clone)]
pub struct HtSig { 
    pub sigs: Vec<XmssSig>,
}

impl HtSig {
    pub fn size(&self) -> usize {
        self.sigs.len() * self.sigs[0].size()
    }
}

pub fn ht_pkgen<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], pk_seed: &[u8]) -> Vec<u8> {
    let adrs = &mut [0u8; 32];
    set_layer_address(adrs, SC::D - 1);
    set_tree_address(adrs, 0);
    let root = xmss_pkgen::<SC>(sk_seed, pk_seed, adrs);
    root
}

pub fn ht_sign<SC: SpxConfig + SpxTweak>(message: &[u8], sk_seed: &[u8], pk_seed: &[u8], mut idx_tree: u64, mut idx_leaf: u32) -> HtSig {
    let adrs = &mut [0u8; 32];

    set_layer_address(adrs, 0);
    set_tree_address(adrs, idx_tree);
    let mut sig_tmp = xmss_sign::<SC>(message, sk_seed, idx_leaf, pk_seed, adrs);
    let mut sig_ht: Vec<XmssSig> = Vec::with_capacity(SC::D as usize);
    let mut root = xmss_pk_from_sig::<SC>(idx_leaf, &sig_tmp, message, pk_seed, adrs);
    sig_ht.push(sig_tmp);

    for j in 1..SC::D {
        //idx_leaf = (idx_tree & ((1 << get_h_prime::<SC>())-1)) as u32; // (h / d) least significat bits of idx_tree
        // idx_leaf = (idx_tree % (1 << get_h_prime::<SC>())) as u32; // (h / d) least significat bits of idx_tree
        // idx_tree = idx_tree >> (SC::H / SC::D); // (h - (j + 1) * (h / d)) most significant bits of idx_tree; ???
        idx_leaf = (idx_tree & (u64::MAX >> (64 - get_h_prime::<SC>() as u64))) as u32;
        let most = (SC::H - (j + 1) * get_h_prime::<SC>()) as u64;
        idx_tree = idx_tree & ((u128::MAX << (64 - most)) as u64);
        set_layer_address(adrs, j);
        set_tree_address(adrs, idx_tree);
        sig_tmp = xmss_sign::<SC>(&root, sk_seed, idx_leaf, pk_seed, adrs);
        if j < SC::D - 1 {
            root = xmss_pk_from_sig::<SC>(idx_leaf, &sig_tmp, &root, pk_seed, adrs);
        }
        sig_ht.push(sig_tmp);
    }

    HtSig { sigs: sig_ht }
}

pub fn ht_verify<SC: SpxConfig + SpxTweak>(message: &[u8], sig_ht: &HtSig, pk_seed: &[u8], mut idx_tree: u64, mut idx_leaf: u32, pk_ht: &[u8]) -> bool {
    let adrs = &mut [0u8; 32];

    let mut sig_tmp = &sig_ht.sigs[0];
    set_layer_address(adrs, 0);
    set_tree_address(adrs, idx_tree);
    let mut node = xmss_pk_from_sig::<SC>(idx_leaf, sig_tmp, message, pk_seed, adrs);

    for j in 1..SC::D {
        //idx_leaf = (idx_tree & ((1 << get_h_prime::<SC>())-1)) as u32;
        //idx_leaf = (idx_tree % (1 << get_h_prime::<SC>())) as u32; // (h / d) least significat bits of idx_tree
        //idx_tree = idx_tree >> (SC::H / SC::D);
        idx_leaf = (idx_tree & (u64::MAX >> (64 - get_h_prime::<SC>() as u64))) as u32;
        let most = (SC::H - (j + 1) * get_h_prime::<SC>()) as u64;
        idx_tree = idx_tree & ((u128::MAX << (64 - most)) as u64);
        sig_tmp = &sig_ht.sigs[j as usize];
        set_layer_address(adrs, j);
        set_tree_address(adrs, idx_tree);
        node = xmss_pk_from_sig::<SC>(idx_leaf, sig_tmp, &node, pk_seed, adrs);
    }

    node == *pk_ht
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::configurations::Spx128fShakeS;
    use crate::utils::sec_rand;

    #[test]
    fn test_hs_sign() {
        let m = sec_rand(Spx128fShakeS::K * (Spx128fShakeS::A + 1));
        let sk_seed = sec_rand(Spx128fShakeS::N);
        let pk_seed = sec_rand(Spx128fShakeS::N);

        let pk = ht_pkgen::<Spx128fShakeS>(&sk_seed, &pk_seed);
        let sig = ht_sign::<Spx128fShakeS>(&m, &sk_seed, &pk_seed, 15017162385220341176, 83);
        let res = ht_verify::<Spx128fShakeS>(&m, &sig, &pk_seed, 15017162385220341176, 83, &pk);

        assert_eq!(res, true);
    }
}