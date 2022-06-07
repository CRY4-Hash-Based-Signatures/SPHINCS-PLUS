use crate::address::{Adrs, AdrsType, set_hash_address, set_chain_address, set_type, set_kp_address, get_kp_address};
use crate::configurations::{SpxConfig, SpxTweak, get_len, get_lg_w, get_len1, get_len2};
use crate::utils::{base_w, to_byte};

fn chain<SC: SpxConfig + SpxTweak>(x: &[u8], start: u32, steps: u32, pk_seed: &[u8], adrs: &mut Adrs) -> Result<Vec<u8>, String> {
    if steps == 0 {
        return Ok(x.to_vec())
    }
    if (start + steps) > (SC::W - 1) {
        return Err("Start index + amount of steps exceed the Winternitz paramter - 1".to_string())
    }

    set_hash_address(adrs, start);
    let mut res = SC::f(pk_seed, adrs, &x);
    for i in 2..(steps + 1) {
        set_hash_address(adrs, start + i - 1);
        res = SC::f(pk_seed, adrs, &res);
    }
    Ok(res)
}

pub fn _wots_skgen<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], adrs: &mut Adrs) -> Vec<Vec<u8>> {
    let len = get_len::<SC>();
    /*
    let mut sk = Vec::with_capacity(len as usize);
    for i in 0..len {
        set_chain_address(adrs, i);
        set_hash_address(adrs, 0);
        sk.push(SC::prf(&sk_seed, adrs))
    }
    */

    let pr = 20;
    let threads = len / pr;
    let sk = crossbeam::scope(|scope| {
        let mut n = Vec::with_capacity(len as usize);
        let mut spawn = Vec::with_capacity(threads as usize);
        for i in 0..threads {
            let mut a = adrs.clone();
            let thread = scope.spawn(move |_| {
                
                let values = if (i as u32 *pr as u32) < len {pr} else {len - (i as u32 *pr as u32)};

                let mut sk_part = Vec::with_capacity(pr as usize);
                for j in 0..(values as usize) {
                    set_chain_address(&mut a, i as u32 *pr + j as u32);
                    set_hash_address(&mut a, 0);
                    sk_part.push(SC::prf(&sk_seed, &mut a));
                }
                sk_part
            });
            spawn.push(thread);
        }

        for t in spawn {
            n.extend(t.join().unwrap());
        }
        n
    }).unwrap();

/*
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
*/

    sk
}

pub fn wots_pkgen<SC: SpxConfig + SpxTweak>(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let len = get_len::<SC>();
    let wots_pk_adrs = &mut adrs.clone();
    // let mut tmp = Vec::with_capacity((len * SC::N) as usize);
    
    // for i in 0..len {
    //     set_chain_address(adrs, i);
    //     set_hash_address(adrs, 0);
    //     let sk = SC::prf(&sk_seed, adrs);
    //     tmp.extend(chain::<SC>(&sk, 0, SC::W - 1, pk_seed, adrs).unwrap());
    // }
    

    //Multithread
    let pr = len/2+1;
    let threads = (len + pr-1 ) / pr;
    //println!("threads {}",threads);
    let tmp = crossbeam::scope(|scope| {
        let mut n = Vec::with_capacity((len * SC::N) as usize);
        let mut spawn = Vec::with_capacity(threads as usize);
        for i in 0..threads {
            //println!{"thread number {}", i}
            let mut a = adrs.clone();
            let thread = scope.spawn(move |_| {
                
                let values = if ((i+1) as u32 *pr as u32) < len {pr} else {len - (i as u32 *pr as u32)};
                //println!{"values {}", values}

                let mut sk_part = Vec::with_capacity((pr * SC::N) as usize);
                for j in 0..(values as usize) {
                    //println!("j {}",j);
                    set_chain_address(&mut a, i as u32 *pr + j as u32);
                    set_hash_address(&mut a, 0);
                    let sk = SC::prf(&sk_seed, &mut a);
                    sk_part.extend(chain::<SC>(&sk, 0, SC::W - 1, pk_seed, &mut a).unwrap());
                }
                sk_part
            });
            spawn.push(thread);
        }

        for t in spawn {
            n.extend(t.join().unwrap());
        }
        n
    }).unwrap();
    //end of multithread

    set_type(wots_pk_adrs, AdrsType::WotsPk);
    set_kp_address(wots_pk_adrs, get_kp_address(adrs));
    let pk = SC::t_l(&pk_seed, wots_pk_adrs, &tmp);
    pk
}

pub fn wots_sign<SC: SpxConfig + SpxTweak>(message: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<Vec<u8>> {
    let lg_w = get_lg_w::<SC>();
    let len1 = get_len1::<SC>();
    let len2 = get_len2::<SC>();
    let len = get_len::<SC>();
    let mut check_sum = 0;
    let mut msg_w = base_w(message, SC::W, len1);

    for i in 0..len1 {
        check_sum += SC::W - 1 - msg_w[i as usize];
    }

    // if (lg_w % 8) != 0 { 
    //     check_sum <<= 8 - ((len2 * lg_w) % 8);
    // }
    check_sum <<= (8 - ((len2 * lg_w) % 8)) % 8;
    let a = len2 * lg_w;
    let len_2_bytes = (a + (8 - 1)) / 8; // (a + (b - 1)) / b
    msg_w.extend(base_w(&to_byte(check_sum, len_2_bytes), SC::W, len2));

    let mut sig = Vec::with_capacity((len * SC::N) as usize);

    for i in 0..len {
        set_chain_address(adrs, i);
        set_hash_address(adrs, 0);
        let tmp_sk = SC::prf(&sk_seed, adrs);
        sig.push(chain::<SC>(&tmp_sk, 0, msg_w[i as usize], &pk_seed, adrs).unwrap());
    }

    sig
}

pub fn wots_pk_from_sig<SC: SpxConfig + SpxTweak>(signature: &Vec<Vec<u8>>, message: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let lg_w = get_lg_w::<SC>();
    let len1 = get_len1::<SC>();
    let len2 = get_len2::<SC>();
    let len = get_len::<SC>();
    let mut check_sum = 0;
    let wots_pk_adrs = &mut adrs.clone();

    let mut msg_w = base_w(message, SC::W, len1);

    for i in 0..len1 {
        check_sum += SC::W - 1 - msg_w[i as usize];
    }

    //check_sum = check_sum << (8 - ((len2 * lg_w) % 8));
    check_sum <<= (8 - ((len2 * lg_w) % 8)) % 8;
    let a = len2 * lg_w;
    let len_2_bytes = (a + (8 - 1)) / 8;
    msg_w.extend(base_w(&to_byte(check_sum, len_2_bytes), SC::W, len2));

    let mut tmp: Vec<u8> = Vec::with_capacity((len * SC::N) as usize);
    for i in 0..len as usize {
        set_chain_address(adrs, i as u32);
        tmp.extend(chain::<SC>(&signature[i], msg_w[i], SC::W - 1 - msg_w[i] as u32, &pk_seed, adrs).unwrap());
    }

    set_type(wots_pk_adrs, AdrsType::WotsPk);
    set_kp_address(wots_pk_adrs, get_kp_address(adrs));
    let pk_sig = SC::t_l(&pk_seed, wots_pk_adrs, &tmp);
    pk_sig
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::sec_rand;
    use crate::configurations::Spx128sShaR;

    #[test]
    fn test_wots_sign() {
        let test_adrs = &mut [0u8; 32];
        let m = sec_rand(Spx128sShaR::N);
        let sk_seed = sec_rand(Spx128sShaR::N);
        let pk_seed = sec_rand(Spx128sShaR::N);

        let pk = wots_pkgen::<Spx128sShaR>(&sk_seed, &pk_seed, test_adrs);
        let sig = wots_sign::<Spx128sShaR>(&m, &sk_seed, &pk_seed, test_adrs);
        let pk_from_sig = wots_pk_from_sig::<Spx128sShaR>(&sig, &m, &pk_seed, test_adrs);

        assert_eq!(pk, pk_from_sig);
    }
}