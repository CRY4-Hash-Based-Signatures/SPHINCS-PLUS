use rand::RngCore;
use sphincs_plus_cry4::{
    Spx, SpxPK, SpxSK, SpxSig, SpxTweak, SpxConfig,

    Spx128sShakeS, Spx128sShakeR, Spx128sShaS, Spx128sShaR, Spx128sBlakeS, Spx128sBlakeR,
    Spx128fShakeS, Spx128fShakeR, Spx128fShaS, Spx128fShaR, Spx128fBlakeS, Spx128fBlakeR,
    
    Spx192sShakeS, Spx192sShakeR, Spx192sShaS, Spx192sShaR,
    Spx192fShakeS, Spx192fShakeR, Spx192fShaS, Spx192fShaR,
    
    Spx256sShakeS, Spx256sShakeR, Spx256sShaS, Spx256sShaR,
    Spx256fShakeS, Spx256fShakeR, Spx256fShaS, Spx256fShaR,
};

use std::{
    io::prelude::*,
    fs::{OpenOptions, File},
    time::{Instant}
};

fn bencher<SC: SpxTweak + SpxConfig>(spx: &Spx<SC>, i: u32, file_to_append: &Option<File>, vers: &str) {
    let test_message = &mut [0u8; 32];
    let mut rng = rand::thread_rng();
    let (mut sk, mut pk): (SpxSK, SpxPK);
    let mut sig: SpxSig;
    let mut kgs = Vec::with_capacity(i as usize);
    let mut sgs = Vec::with_capacity(i as usize);
    let mut ves = Vec::with_capacity(i as usize);

    for _ in 0..i {
        rng.fill_bytes(test_message);
        let now = Instant::now();
        (sk, pk) = spx.keygen();
        let elapsed = now.elapsed();
        kgs.push(elapsed);

        let now = Instant::now();
        sig = spx.sign(test_message, &sk);
        let elapsed = now.elapsed();
        sgs.push(elapsed);

        let now = Instant::now();
        spx.verify(test_message, sig, &pk);
        let elapsed = now.elapsed();
        ves.push(elapsed);
    }

    let av_kg = kgs.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    let av_sig = sgs.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    let av_ver = ves.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;

    let a = 1000.0;
    match file_to_append.as_ref() {
        None => {
            println!("Averaging over {} times, the times are\nKeygen:\t\t{:.3?}\nSigning:\t{:.3?}\nVerifying:\t{:.3?}", i, av_kg / a, av_sig / a, av_ver / a);
        }
        Some(mut f) => {
            let kg_str = kgs.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            let sig_str = sgs.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            let ver_str = ves.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            writeln!(f,"{}\nKeygen Times:\t{}\nSigning times:\t{}\nVerify times:\t{}\n", vers, kg_str, sig_str, ver_str).unwrap();
        }
    }
}

fn sphincs_bench(args: &Vec<String>) {
    let times_to_bench: u32 = args[2].parse().unwrap();
    let file_to_append = if args.len() < 4 {
        None
    } else {
        Some(OpenOptions::new().write(true).append(true).open(args[3].as_str()).unwrap())
    };

    let sipi = args[1].as_str();
    
    match sipi {
        "128sShakeS" => { bencher(&Spx::<Spx128sShakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "128sShakeR" => { bencher(&Spx::<Spx128sShakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "128sShaS" =>   { bencher(&Spx::<Spx128sShaS>::new(true), times_to_bench, &file_to_append, sipi); }
        "128sShaR" =>   { bencher(&Spx::<Spx128sShaR>::new(true), times_to_bench, &file_to_append, sipi); }
        "128sBlakeS" => { bencher(&Spx::<Spx128sBlakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "128sBlakeR" => { bencher(&Spx::<Spx128sBlakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "128fShakeS" => { bencher(&Spx::<Spx128fShakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "128fShakeR" => { bencher(&Spx::<Spx128fShakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "128fShaS" =>   { bencher(&Spx::<Spx128fShaS>::new(true), times_to_bench, &file_to_append, sipi); }
        "128fShaR" =>   { bencher(&Spx::<Spx128fShaR>::new(true), times_to_bench, &file_to_append, sipi); }
        "128fBlakeS" => { bencher(&Spx::<Spx128fBlakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "128fBlakeR" => { bencher(&Spx::<Spx128fBlakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        
        "192sShakeS" => { bencher(&Spx::<Spx192sShakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "192sShakeR" => { bencher(&Spx::<Spx192sShakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "192sShaS" =>   { bencher(&Spx::<Spx192sShaS>::new(true), times_to_bench, &file_to_append, sipi); }
        "192sShaR" =>   { bencher(&Spx::<Spx192sShaR>::new(true), times_to_bench, &file_to_append, sipi); }
        "192fShakeS" => { bencher(&Spx::<Spx192fShakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "192fShakeR" => { bencher(&Spx::<Spx192fShakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "192fShaS" =>   { bencher(&Spx::<Spx192fShaS>::new(true), times_to_bench, &file_to_append, sipi); }
        "192fShaR" =>   { bencher(&Spx::<Spx192fShaR>::new(true), times_to_bench, &file_to_append, sipi); }
        
        "256sShakeS" => { bencher(&Spx::<Spx256sShakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "256sShakeR" => { bencher(&Spx::<Spx256sShakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "256sShaS" =>   { bencher(&Spx::<Spx256sShaS>::new(true), times_to_bench, &file_to_append, sipi); }
        "256sShaR" =>   { bencher(&Spx::<Spx256sShaR>::new(true), times_to_bench, &file_to_append, sipi); }
        "256fShakeS" => { bencher(&Spx::<Spx256fShakeS>::new(true), times_to_bench, &file_to_append, sipi); }
        "256fShakeR" => { bencher(&Spx::<Spx256fShakeR>::new(true), times_to_bench, &file_to_append, sipi); }
        "256fShaS" =>   { bencher(&Spx::<Spx256fShaS>::new(true), times_to_bench, &file_to_append, sipi); }
        "256fShaR" =>   { bencher(&Spx::<Spx256fShaR>::new(true), times_to_bench, &file_to_append, sipi); }

        "all" => {
            writeln!(file_to_append.as_ref().unwrap(), "instance, keygen time, signing time, verifying time").unwrap();
            bencher(&Spx::<Spx128sShakeS>::new(true), times_to_bench, &file_to_append, "ShakeS128s");   println!("Finished {}", "ShakeS128s");
            bencher(&Spx::<Spx128sShakeR>::new(true), times_to_bench, &file_to_append, "ShakeR128s");   println!("Finished {}", "ShakeR128s");
            bencher(&Spx::<Spx128sShaS>::new(true), times_to_bench, &file_to_append, "ShaS128s");       println!("Finished {}", "ShaS128s");
            bencher(&Spx::<Spx128sShaR>::new(true), times_to_bench, &file_to_append, "ShaR128s");       println!("Finished {}", "ShaR128s");
            bencher(&Spx::<Spx128sBlakeS>::new(true), times_to_bench, &file_to_append, "BlakeS128s");   println!("Finished {}", "BlakeS128s");
            bencher(&Spx::<Spx128sBlakeR>::new(true), times_to_bench, &file_to_append, "BlakeR128s");   println!("Finished {}", "BlakeR128s");
            bencher(&Spx::<Spx128fShakeS>::new(true), times_to_bench, &file_to_append, "ShakeS128f");   println!("Finished {}", "ShakeS128f");
            bencher(&Spx::<Spx128fShakeR>::new(true), times_to_bench, &file_to_append, "ShakeR128f");   println!("Finished {}", "ShakeR128f");
            bencher(&Spx::<Spx128fShaS>::new(true), times_to_bench, &file_to_append, "ShaS128f");       println!("Finished {}", "ShaS128f");
            bencher(&Spx::<Spx128fShaR>::new(true), times_to_bench, &file_to_append, "ShaR128f");       println!("Finished {}", "ShaR128f");
            bencher(&Spx::<Spx128fBlakeS>::new(true), times_to_bench, &file_to_append, "BlakeS128f");   println!("Finished {}", "BlakeS128f");
            bencher(&Spx::<Spx128fBlakeR>::new(true), times_to_bench, &file_to_append, "BlakeR128f");   println!("Finished {}", "BlakeR128f");

            bencher(&Spx::<Spx192sShakeS>::new(true), times_to_bench, &file_to_append, "ShakeS192s");   println!("Finished {}", "ShakeS192s");
            bencher(&Spx::<Spx192sShakeR>::new(true), times_to_bench, &file_to_append, "ShakeR192s");   println!("Finished {}", "ShakeR192s");
            bencher(&Spx::<Spx192sShaS>::new(true), times_to_bench, &file_to_append, "ShaS192s");       println!("Finished {}", "ShaS192s");
            bencher(&Spx::<Spx192sShaR>::new(true), times_to_bench, &file_to_append, "ShaR192s");       println!("Finished {}", "ShaR192s");
            bencher(&Spx::<Spx192fShakeS>::new(true), times_to_bench, &file_to_append, "ShakeS192f");   println!("Finished {}", "ShakeS192f");
            bencher(&Spx::<Spx192fShakeR>::new(true), times_to_bench, &file_to_append, "ShakeR192f");   println!("Finished {}", "ShakeR192f");
            bencher(&Spx::<Spx192fShaS>::new(true), times_to_bench, &file_to_append, "ShaS192f");       println!("Finished {}", "ShaS192f");
            bencher(&Spx::<Spx192fShaR>::new(true), times_to_bench, &file_to_append, "ShaR192f");       println!("Finished {}", "ShaR192f");

            bencher(&Spx::<Spx256sShakeS>::new(true), times_to_bench, &file_to_append, "ShakeS256s");   println!("Finished {}", "ShakeS256s");
            bencher(&Spx::<Spx256sShakeR>::new(true), times_to_bench, &file_to_append, "ShakeR256s");   println!("Finished {}", "ShakeR256s");
            bencher(&Spx::<Spx256sShaS>::new(true), times_to_bench, &file_to_append, "ShaS256s");       println!("Finished {}", "ShaS256s");
            bencher(&Spx::<Spx256sShaR>::new(true), times_to_bench, &file_to_append, "ShaR256s");       println!("Finished {}", "ShaR256s");
            bencher(&Spx::<Spx256fShakeS>::new(true), times_to_bench, &file_to_append, "ShakeS256f");   println!("Finished {}", "ShakeS256f");
            bencher(&Spx::<Spx256fShakeR>::new(true), times_to_bench, &file_to_append, "ShakeR256f");   println!("Finished {}", "ShakeR256f");
            bencher(&Spx::<Spx256fShaS>::new(true), times_to_bench, &file_to_append, "ShaS256f");       println!("Finished {}", "ShaS256f");
            bencher(&Spx::<Spx256fShaR>::new(true), times_to_bench, &file_to_append, "ShaR256f");       println!("Finished {}", "ShaR256f");
        }
       _ => panic!("something went wrong:) {} instance doesn't exists", sipi)
    }
}

fn rsa_bench(i: u32, bits: usize, file_to_append: &str) {
    use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};
    use sha2::Digest;
    let mut bench_message = [0u8; 32];

    let mut rng = rand::thread_rng();
    let mut sk;
    let mut pk;
    let mut sig;

    let mut kgs = Vec::with_capacity(i as usize);
    let mut sgs = Vec::with_capacity(i as usize);
    let mut ves = Vec::with_capacity(i as usize);

    for step in 0..i {
        rng.fill_bytes(&mut bench_message);
        let d = &sha2::Sha256::digest(bench_message);
        let now = Instant::now();
        sk = RsaPrivateKey::new(&mut rng, bits).unwrap();
        pk = RsaPublicKey::from(&sk);
        let elapsed = now.elapsed();
        kgs.push(elapsed);
        println!("Finished generating key {}", step + 1);

        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));

        let now = Instant::now();
        sig = sk.sign(padding, d).unwrap();
        let elapsed = now.elapsed();
        sgs.push(elapsed);

        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));

        let now = Instant::now();
        pk.verify(padding, d, &sig).unwrap();
        let elapsed = now.elapsed();
        ves.push(elapsed);
    }

    let av_kg = kgs.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    let av_sig = sgs.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    let av_ver = ves.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;

    let a = 1000.0;
    match file_to_append {
        "" => {
            println!("RSA - Averaging over {} times, the times are\nKeygen:\t\t{:.3?}\nSigning:\t{:.3?}\nVerifying:\t{:.3?}", i, av_kg / a, av_sig / a, av_ver / a);
        }
        _ => {
            let mut f = OpenOptions::new().write(true).append(true).open(file_to_append).unwrap();

            let kg_str = kgs.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            let sig_str = sgs.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            let ver_str = ves.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            writeln!(f,"{}\nKeygen Times:\t{}\nSigning times:\t{}\nVerify times:\t{}\n", "RSA", kg_str, sig_str, ver_str).unwrap();
        }
    }
}

fn ecdsa_bench(i: u32, file_to_append: &str) {
    use k256::{
        ecdsa::{SigningKey, Signature, signature::Signer},
        
    };
    use k256::ecdsa::{VerifyingKey, signature::Verifier};
    let test_message = &mut [0u8; 32];

    let mut rng = rand::thread_rng();
    let mut sk;
    let mut pk;
    let mut sig: Signature;

    let mut kgs = Vec::with_capacity(i as usize);
    let mut sgs = Vec::with_capacity(i as usize);
    let mut ves = Vec::with_capacity(i as usize);

    for _ in 0..i {
        rng.fill_bytes(test_message);
        let now = Instant::now();
        sk = SigningKey::random(&mut rng);
        pk = VerifyingKey::from(&sk);
        let elapsed = now.elapsed();
        kgs.push(elapsed);

        let now = Instant::now();
        sig = sk.sign(test_message);
        let elapsed = now.elapsed();
        sgs.push(elapsed);

        let now = Instant::now();
        pk.verify(test_message, &sig).unwrap();
        let elapsed = now.elapsed();
        ves.push(elapsed);
    }

    let av_kg = kgs.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    let av_sig = sgs.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    let av_ver = ves.iter().fold(0, |sum, &val| sum + val.as_micros()) as f64 / i as f64;
    
    let a = 1000.0;
    match file_to_append {
        "" => {
            println!("ECDSA - Averaging over {} times, the times are\nKeygen:\t\t{:.3?}\nSigning:\t{:.3?}\nVerifying:\t{:.3?}", i, av_kg / a, av_sig / a, av_ver / a);
        }
        _ => {
            let mut f = OpenOptions::new().write(true).append(true).open(file_to_append).unwrap();

            let kg_str = kgs.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            let sig_str = sgs.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            let ver_str = ves.iter().map(|&dur| (dur.as_micros() as f64 / a).to_string())
                                                            .reduce(|cur, nxt| cur + "\t" + &nxt).unwrap();
            writeln!(f,"{}\nKeygen Times:\t{}\nSigning times:\t{}\nVerify times:\t{}\n", "ECDSA", kg_str, sig_str, ver_str).unwrap();
        }
    }
}

fn main() {
    //ecdsa_bench(100, "D:\\Git\\amper-sphincs-plus\\benchmarks\\new_native_100_ecdsa.txt");
    //rsa_bench(100, 3072, "D:\\Git\\amper-sphincs-plus\\benchmarks\\new_native_100_rsa3072.txt");

    let args = vec![String::from(""), String::from("all"), 
        String::from("100"), String::from("D:\\Git\\amper-sphincs-plus\\benchmarks\\new_native_100_2thread.txt")];

    sphincs_bench(&args);
}