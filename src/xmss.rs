use crate::address::{Adrs, AdrsType, set_type, set_kp_address, set_tree_height, set_tree_index, get_tree_index, get_tree_height};
use crate::wots::{wots_pkgen, wots_sign, wots_pk_from_sig};
use crate::utils::Node;
use crate::configurations::{SpxConfig, SpxTweak, get_h_prime};

#[derive(Clone, Debug)]
pub struct XmssSig {
    pub wots_sig: Vec<Vec<u8>>,
    pub auth_path: Vec<Vec<u8>>,
}

impl XmssSig {
    pub fn size(&self) -> usize {
        (self.wots_sig.len() * self.wots_sig[0].len()) +
        (self.auth_path.len() * self.auth_path[0].len())
    }
}

fn tree_hash<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], start: u32, tar_height: u32, pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    if tar_height < 2 {
        tree_hash_aux::<SC>(sk_seed, start, tar_height, pk_seed, adrs)
    } else {
        let c_adrs = &mut adrs.clone();
        let upper = 2u32.pow(tar_height);
        let node = crossbeam::scope(|scope| {
            let h1 = scope.spawn(|_| {
                tree_hash_aux::<SC>(sk_seed, start, tar_height - 1, pk_seed, c_adrs)
            });
            let h2 = scope.spawn(|_| {
                tree_hash_aux::<SC>(sk_seed, start + upper / 2, tar_height - 1, pk_seed, adrs)
            });
            let mut n1 = h1.join().unwrap();
            let n2 = h2.join().unwrap();
            n1.extend(n2);
            n1
        }).unwrap();
        
        set_tree_index(adrs, (get_tree_index(adrs) - 1) / 2);
        SC::h(&pk_seed, adrs, &node)
    }
}

fn tree_hash_aux<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], start: u32, tar_height: u32, pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    if start % (1 << tar_height) != 0 {
        panic!("Cannot compute tree_hash when wots index node is not leftmost node of wots tree")
    }

    let upper = 2u32.pow(tar_height);
    let mut node_stack: Vec<Node> = Vec::with_capacity(tar_height as usize);

    let mut height;

    for i in 0..upper {
        set_type(adrs, AdrsType::WotsHash);
        set_kp_address(adrs, start + i);
        let mut node = wots_pkgen::<SC>(sk_seed, pk_seed, adrs);
        height = 0;
        set_type(adrs, AdrsType::Tree);

        set_tree_height(adrs, 1);
        set_tree_index(adrs, start + i);

        while node_stack.len() > 0 && node_stack.last().unwrap().height == height {
            set_tree_index(adrs, (get_tree_index(adrs) - 1) / 2);
            let conc = [node_stack.pop().unwrap().value, node].concat();

            node = SC::h(pk_seed, adrs, &conc);
            height += 1;

            set_tree_height(adrs, get_tree_height(adrs) + 1);
        }
        node_stack.push(Node { value: node, height });
    }

    node_stack.pop().unwrap().value
}

pub fn xmss_pkgen<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    tree_hash::<SC>(sk_seed, 0, get_h_prime::<SC>(), pk_seed, adrs)
}

pub fn xmss_sign<SC: SpxConfig + SpxTweak>(message: &[u8], sk_seed: &[u8], idx: u32, pk_seed: &[u8], adrs: &mut Adrs) -> XmssSig {
    let h_prime = get_h_prime::<SC>();
    let mut auth_path = Vec::with_capacity(h_prime as usize);

    for j in 0..h_prime {
        let k = (idx / 2u32.pow(j)) ^ 1;
        let node = tree_hash::<SC>(sk_seed, k * 2u32.pow(j), j, pk_seed, adrs);
        auth_path.push(node);
    }

    set_type(adrs, AdrsType::WotsHash);
    set_kp_address(adrs, idx);
    let wots_sig = wots_sign::<SC>(message, sk_seed, pk_seed, adrs);

    XmssSig { wots_sig, auth_path }
}

pub fn xmss_pk_from_sig<SC: SpxConfig + SpxTweak>(idx: u32, xmss_sig: &XmssSig, message: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    set_type(adrs, AdrsType::WotsHash);
    set_kp_address(adrs, idx);
    let sig = &xmss_sig.wots_sig;
    let auth_path = &xmss_sig.auth_path;
    let mut node0 = wots_pk_from_sig::<SC>(sig, message, &pk_seed, adrs);
    let mut concat_m: Vec<u8> = vec![0; (SC::N * 2) as usize];

    set_type(adrs, AdrsType::Tree);
    set_tree_index(adrs, idx);
    let h_prime = get_h_prime::<SC>();
    for k in 0..h_prime {
        set_tree_height(adrs, k + 1);

        if (idx / 2u32.pow(k)) % 2 == 0 {
            set_tree_index(adrs, get_tree_index(adrs) / 2);
            concat_m.splice(..SC::N as usize, node0);
            concat_m.splice(SC::N as usize.., auth_path[k as usize].iter().cloned());
            node0 = SC::h(&pk_seed, adrs, &concat_m);
        } else {
            set_tree_index(adrs, (get_tree_index(adrs) - 1) / 2);
            concat_m.splice(..SC::N as usize, auth_path[k as usize].iter().cloned());
            concat_m.splice(SC::N as usize.., node0);
            node0 = SC::h(&pk_seed, adrs, &concat_m);
        }
    }
    node0
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::sec_rand;
    use crate::configurations::Spx128sShakeS;

    #[test]
    fn test_xmss_sign() {
        let test_adrs = &mut [0u8; 32];
        let m = sec_rand(Spx128sShakeS::N);
        let sk_seed = sec_rand(Spx128sShakeS::N);
        let pk_seed = sec_rand(Spx128sShakeS::N);

        let pk = xmss_pkgen::<Spx128sShakeS>(&sk_seed, &pk_seed, &mut test_adrs.clone());
        let sig = xmss_sign::<Spx128sShakeS>(&m, &sk_seed, 214, &pk_seed, &mut test_adrs.clone());
        let pk_from_sig = xmss_pk_from_sig::<Spx128sShakeS>(214, &sig, &m, &pk_seed, &mut test_adrs.clone());

        assert_eq!(pk, pk_from_sig);
    }

    #[test]
    fn test_xmss_sign_uneven() {
        let test_adrs = &mut [0u8; 32];
        let m = sec_rand(Spx128sShakeS::N);
        let sk_seed = sec_rand(Spx128sShakeS::N);
        let pk_seed = sec_rand(Spx128sShakeS::N);

        let pk = xmss_pkgen::<Spx128sShakeS>(&sk_seed, &pk_seed, &mut test_adrs.clone());
        let sig = xmss_sign::<Spx128sShakeS>(&m, &sk_seed, 83, &pk_seed, &mut test_adrs.clone());
        let pk_from_sig = xmss_pk_from_sig::<Spx128sShakeS>(83, &sig, &m, &pk_seed, &mut test_adrs.clone());

        assert_eq!(pk, pk_from_sig);
    }

    // #[test]
    // fn test_hash_with_thread() {
    //     let test_adrs = &mut [0u8; 32];
    //     let sk_seed = sec_rand(Spx128sShakeS::N);
    //     let pk_seed = sec_rand(Spx128sShakeS::N);

    //     let start = 128;
    //     let tar_height = 7;
    //     let one = tree_hash_aux::<Spx128sShakeS>(&sk_seed, start, tar_height, &pk_seed, test_adrs);
    //     let two = tree_hash::<Spx128sShakeS>(&sk_seed, start, tar_height, &pk_seed, &mut test_adrs.clone());

    //     assert_eq!(one, two);
    // }
}