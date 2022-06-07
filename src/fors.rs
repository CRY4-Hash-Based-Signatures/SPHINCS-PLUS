use crate::address::{Adrs, AdrsType, set_tree_height, set_tree_index, get_tree_index, get_tree_height, set_type, set_kp_address, get_kp_address};
use crate::configurations::{SpxConfig, SpxTweak, get_t};
use crate::utils::Node;

/*
idx: The index of the j'th element in the i'th set. idx = it*j for FORS parameter t
*/
pub fn _fors_skgen<SC: SpxConfig + SpxTweak>(sk_seed: &Vec<u8>, adrs: &mut Adrs, idx: u32) -> Vec<u8> {
    set_tree_height(adrs, 0);
    set_tree_index(adrs, idx);
    let sk = SC::prf(sk_seed, adrs);
    sk
}


/// sk_seed:    The secret key seed
/// s:          Start index
/// z:          Heigth of target node
/// pk_seed:    The public key seed
/// adrs:       The address of the FORS tree 
/// 
/// outputs the rootnode of the FORS tree

fn fors_treehash<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], start: u32, tar_height: u32, pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    if tar_height < 2 {
        fors_treehash_aux::<SC>(sk_seed, start, tar_height, pk_seed, adrs)
    } else {
        let c_adrs = &mut adrs.clone();
        let upper = 2u32.pow(tar_height);
        let node = crossbeam::scope(|scope| {
            let h1 = scope.spawn(|_| {
                fors_treehash_aux::<SC>(sk_seed, start, tar_height - 1, pk_seed, c_adrs)
            });
            let h2 = scope.spawn(|_| {
                fors_treehash_aux::<SC>(sk_seed, start + upper / 2, tar_height - 1, pk_seed, adrs)
            });
            let mut n1 = h1.join().unwrap();
            let n2 = h2.join().unwrap();
            n1.extend(n2);
            n1
        }).unwrap();

        set_tree_index(adrs, (get_tree_index(adrs) - 1) / 2);
        SC::h(pk_seed, adrs, &node)
    }
}

fn fors_treehash_aux<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], start: u32, tar_height: u32, pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    // The node has to be a leftmost leaf
    if start % (1 << tar_height) != 0 { 
        panic!("Node has to be leftmost leaf")
    }

    let upper = 2u32.pow(tar_height);
    let mut node_stack: Vec<Node> = Vec::with_capacity(tar_height as usize);

    let mut height;

    for i in 0..upper {
        set_tree_height(adrs, 0);
        set_tree_index(adrs, start + i);
        let sk = SC::prf(sk_seed, adrs);
        let mut node = SC::f(pk_seed, adrs, &sk);
        height = 0;

        set_tree_height(adrs, 1);
        set_tree_index(adrs, start + i);

        // while top node on stack has same height as node variable / address height
        while node_stack.len() > 0 && node_stack.last().unwrap().height == height {
            set_tree_index(adrs, (get_tree_index(adrs) - 1) / 2);
            let conc = [node_stack.pop().unwrap().value, node].concat();
            
            node = SC::h(pk_seed, adrs, &conc);
            height += 1;

            set_tree_height(adrs, get_tree_height(adrs) + 1);
        }
        node_stack.push(Node { value: node, height })
    } 
    
    node_stack.pop().unwrap().value
}

/// 
pub fn _fors_pkgen<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let t = get_t::<SC>();
    let fors_pk_adrs = &mut adrs.clone();

    let mut root = Vec::with_capacity((SC::K*SC::N) as usize);

    for i in 0..SC::K {
        root.extend(fors_treehash::<SC>(sk_seed, i*t, SC::A, pk_seed, adrs));
    }

    set_type(fors_pk_adrs, AdrsType::ForsRoot);
    set_kp_address(fors_pk_adrs, get_kp_address(adrs));
    let pk = SC::t_l(pk_seed, fors_pk_adrs, &root);

    pk
}

fn message_to_indices<SC: SpxConfig>(message: &[u8]) -> Vec<u32> {
    let mut offset = 0;
    let mut res: Vec<u32> = Vec::with_capacity(SC::K as usize);
    for i in 0..SC::K {
        res.push(0);
        for j in 0..SC::A {
            res[i as usize] ^= (((message[offset >> 3] as u32) >> (offset & 0x7)) & 0x1) << j;
            offset += 1;
        }
    }
    res
}

#[derive(Clone)]
pub struct ForsSig {
    pub auth_trees: Vec<AuthTree>,
}

impl ForsSig {
    pub fn size(&self) -> usize {
        self.auth_trees.len() * self.auth_trees[0].size()
    }
}

#[derive(Clone, Debug)]
pub struct AuthTree {
    pub sk_value: Vec<u8>,
    pub auth_path: Vec<Vec<u8>>
}

impl AuthTree {
    pub fn size(&self) -> usize {
        self.sk_value.len() + (self.auth_path.len() * self.auth_path[0].len())
    }
}

pub fn fors_sign<SC: SpxConfig + SpxTweak>(message: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> ForsSig {
    let t = get_t::<SC>();
    let mut sig = ForsSig { auth_trees: Vec::with_capacity(SC::K as usize) };
    let indices = message_to_indices::<SC>(&message);

    for (i, &idx) in indices.iter().enumerate() {
        // Get pk_value
        set_tree_height(adrs, 0);
        set_tree_index(adrs, (i as u32)*t + idx);
        let sk_value = SC::prf(sk_seed, adrs);

        // Get authentication path
        let mut auth_path: Vec<Vec<u8>> = Vec::with_capacity(SC::A as usize);

        for j in 0..SC::A {
            let s = (idx / 2u32.pow(j)) ^ 1;
            auth_path.push(fors_treehash::<SC>(sk_seed, (i as u32) * t + s * 2u32.pow(j), j, pk_seed, adrs))
        }
        let auth_tree = AuthTree{ sk_value, auth_path };
        sig.auth_trees.push(auth_tree);
    }

    sig
}

pub fn fors_pk_from_sig<SC: SpxConfig + SpxTweak>(fors_sig: &ForsSig, message: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let t = get_t::<SC>();
    let indices = message_to_indices::<SC>(message);
    let mut root: Vec<u8> = Vec::with_capacity((SC::K * SC::N) as usize);
    let mut concat_m = vec![0; (2 * SC::N) as usize];

    for (i, &idx) in indices.iter().enumerate() {
        // Compute leaf
        let sk = &fors_sig.auth_trees[i].sk_value;
        set_tree_height(adrs, 0);
        set_tree_index(adrs, (i as u32)*t + idx);
        let mut node0 = SC::f(pk_seed, adrs, sk);

        let auth = &fors_sig.auth_trees[i].auth_path;
        //set_tree_index(adrs, (i as u32)*t + idx);
        for j in 0..SC::A {
            set_tree_height(adrs, j + 1);
            if idx / (2u32.pow(j)) % 2 == 0 {
                set_tree_index(adrs, get_tree_index(adrs) / 2);
                concat_m.splice(..SC::N as usize, node0);
                concat_m.splice(SC::N as usize.., auth[j as usize].iter().cloned());
                node0 = SC::h(pk_seed, adrs, &concat_m);
            } else {
                set_tree_index(adrs, (get_tree_index(adrs) - 1) / 2);
                concat_m.splice(..SC::N as usize, auth[j as usize].iter().cloned());
                concat_m.splice(SC::N as usize.., node0);
                node0 = SC::h(pk_seed, adrs, &concat_m);
            }
        }
        root.extend(node0);
    }
    
    let fors_pk_adrs = &mut adrs.clone();
    set_type(fors_pk_adrs, AdrsType::ForsRoot);
    set_kp_address(fors_pk_adrs, get_kp_address(adrs));
    let pk = SC::t_l(pk_seed, fors_pk_adrs, &root);

    pk
}

#[cfg(test)]
mod test {
    use crate::utils::sec_rand;
    use crate::configurations::Spx128sShaR;

    use super::*;

    #[test]
    fn test_message_to_indicies() {
        let mut message = [0;40];
        message[39] = 1 << 2;
        let res = message_to_indices::<Spx128sShaR>(&message);

       
        println!("{:?}", res);
        //assert!(false)
    }

    #[test]
    fn test_fors_sign_verify() {
        let test_adrs = &mut [0u8; 32];
        set_type(test_adrs, AdrsType::ForsTree);
        let m = sec_rand(50);
        let sk_seed = sec_rand(Spx128sShaR::N);
        let pk_seed = sec_rand(Spx128sShaR::N);

        let pk = _fors_pkgen::<Spx128sShaR>(&sk_seed, &pk_seed, test_adrs);
        let sig = fors_sign::<Spx128sShaR>(&m, &sk_seed, &pk_seed, test_adrs);
        let pk_sig = fors_pk_from_sig::<Spx128sShaR>(&sig, &m, &pk_seed, test_adrs);

        assert_eq!(pk, pk_sig);
    }
}