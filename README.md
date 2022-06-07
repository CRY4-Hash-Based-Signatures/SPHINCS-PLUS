# SPHINCS-PLUS
Implementation of the hash based signature scheme SPHINCS+ in Rust. SPHINCS+ is a post-quantum signature scheme, submitted to the NIST-PQ competition. 
For more information visit: https://sphincs.org/

## Usage

    use sphincs_plus_cry4::{Spx, Spx128fBlakeR};
    let message = b"Hi there!";

    let spx_instance = Spx::<Spx128fBlakeR>::new(true);
    let (sk, pk) = spx_instance.keygen();
    
    let sig = spx_instance.sign(message, &sk);
    spx_instance.verify(message, sig, &pk);
    
## Benchmark

To build the benchmark file run:

    cargo build --features build-binary --bin benchmark
