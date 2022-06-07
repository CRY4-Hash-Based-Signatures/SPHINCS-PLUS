use rand::RngCore;

pub struct Node {
    pub value: Vec<u8>,
    pub height: u32,
}

pub fn to_byte(x: u32, y: u32) -> Vec<u8> {
    let mut res = vec![0u8; y as usize];
    let boats = x.to_be_bytes();
    let range = res.len().min(boats.len());

    for i in 0..range {
        res[y as usize -1-i] = boats[boats.len()-1-i]
    }

    res
}

pub fn base_w(message: &[u8], w: u32, out_len: u32) -> Vec<u32> {
    let mut inv = 0;
    let mut out = 0;
    let mut total: u32 = 0;
    let mut bits = 0;
    let lg_w = match w {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!("Cannot compute base-w with w: {} not in {{4,16,256}}", w)
    };

    let mut base_w_x = vec![0; out_len as usize];

    for _ in 0..out_len {
        if bits == 0 {
            total = message[inv] as u32;
            inv += 1;
            bits += 8;
        }
        bits -= lg_w;
        base_w_x[out] = (total >> bits) & (w - 1);
        out += 1;
    }

    base_w_x
}

/// Generates a cryptograpic random byte vector of a given size
pub fn sec_rand(size: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut byte_array = vec![0; size as usize];
    
    rng.fill_bytes(&mut byte_array);

    byte_array
}

fn vec_to_array<const N: usize>(vec: Vec<u8>) -> [u8; N]{
    let mut array: [u8; N] = [0; N];

    let range = if N > vec.len() {
        vec.len()
    } else {
        N
    };

    for i in 0..range {
        array[N-1-i] = vec[vec.len()-1-i]
    }

    array
}

pub fn vec_to_u32(vec: Vec<u8>) -> u32 {
    let array = vec_to_array::<4>(vec);
    u32::from_be_bytes(array)
}

pub fn vec_to_u64(vec: Vec<u8>) -> u64 {
    let array = vec_to_array::<8>(vec);
    u64::from_be_bytes(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes_len() {
        let x = 10;
        let y = 2;

        let to = to_byte(x, y);
        println!("{:?}",to);
        assert_eq!(to.len(), y as usize)
    }

    #[test]
    fn test_to_bytes_val() {
        let x1 = 256;
        let x2 = 255;
        let y1 = 2;
        let y2 = 4;

        let to1 = to_byte(x1, y1);
        let to2 = to_byte(x2, y2);
        println!("{:?}",to1);
        assert_eq!(to1,[1,0]);
        assert_eq!(to2,[0,0,0,255])
    }

    #[test]
    fn test_to_bytes_x_too_large() {
        let x = 0x1FFFF;
        let y = 2;

        let to = to_byte(x, y);
        println!("{:?}",to);
        assert_eq!(to,[0xFF,0xFF])
    }

    #[test]
    fn test_base_w() {
        let v = vec![1,1,20,1];
        let res = base_w(&v, 16, 8);

        assert_eq!(res, vec![0,1,0,1,1,4,0,1])
    }

    #[test]
    fn test_base_w_len() {
        let v = vec![1,1,20,1];
        let res = base_w(&v, 16, 4);

        // IS this rigth?
        assert_eq!(res, vec![0,1,0,1])
    }

    #[test]
    fn test_vec_to_u32(){
        let v:Vec<u8> = vec![0,0,1,1];
        let u = vec_to_u32(v);

        assert_eq!(u,257);
    }

    #[test]
    fn test_vec_to_u64(){
        let v:Vec<u8> = vec![0,0,1,1];
        let u = vec_to_u64(v);

        assert_eq!(u,257);
    }

    #[test]
    fn test_vec_to_u32_long(){
        let v:Vec<u8> = vec![1,0xFF,0xAB,0xAA,0xFF];
        let u = vec_to_u32(v);

        assert_eq!(u,0xFFABAAFF);
    }
}