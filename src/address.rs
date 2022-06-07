pub enum AdrsType {
    WotsHash = 0,
    WotsPk,
    Tree,
    ForsTree,
    ForsRoot,
}

pub type Adrs = [u8; 32];

pub fn get_kp_address(adrs: &Adrs) -> u32 {
    u32::from_be_bytes(adrs[20..24].try_into().unwrap())
}

pub fn get_tree_height(adrs: &Adrs) -> u32 {
    u32::from_be_bytes(adrs[24..28].try_into().unwrap())
}

pub fn get_tree_index(adrs: &Adrs) -> u32 {
    u32::from_be_bytes(adrs[28..].try_into().unwrap())
}

fn _get_layer_address(adrs: &Adrs) -> u32 {
    u32::from_be_bytes(adrs[0..4].try_into().unwrap())
}

pub fn set_layer_address(adrs: &mut Adrs, new_layer_address: u32) {
    adrs[0..4].copy_from_slice(&new_layer_address.to_be_bytes());
}

//We do not used the last byte
pub fn set_tree_address(adrs: &mut Adrs, new_tree_address: u64) { // CHANGE SIGNATURE LATER... For our purpose, will always be an u64
    adrs[4..8].copy_from_slice(&[0; 4]);
    adrs[8..16].copy_from_slice(&new_tree_address.to_be_bytes());
}

pub fn set_kp_address(adrs: &mut Adrs, new_kp_address: u32) {
    adrs[20..24].copy_from_slice(&new_kp_address.to_be_bytes());
}

pub fn set_type(adrs: &mut Adrs, new_type: AdrsType) {
    adrs[16..20].copy_from_slice(&(new_type as u32).to_be_bytes());
    adrs[20..].copy_from_slice(&[0u8; 12]);
}

pub fn set_hash_address(adrs: &mut Adrs, new_hash_address: u32) {
    adrs[28..].copy_from_slice(&new_hash_address.to_be_bytes());
}

pub fn set_chain_address(adrs: &mut Adrs, new_chain_address: u32) {
    adrs[24..28].copy_from_slice(&new_chain_address.to_be_bytes());
}

pub fn set_tree_height(adrs: &mut Adrs, new_tree_height: u32) {
    adrs[24..28].copy_from_slice(&new_tree_height.to_be_bytes());
}

pub fn set_tree_index(adrs: &mut Adrs, new_tree_index: u32) {
    adrs[28..].copy_from_slice(&new_tree_index.to_be_bytes());
}

pub fn get_compress(adrs: &Adrs) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::with_capacity(22);
    res.push(adrs[3]);   // Least significant byte of layer address
    res.extend_from_slice(&adrs[8..16]); // Least significant 4 bytes of tree address
    res.push(adrs[19]);  // Least significant byte of type
    res.extend_from_slice(&adrs[20..]);  // Last 12 bytes
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_layer_address_works() {
        let adrs = &mut [0u8; 32];
        set_layer_address(adrs, 32);
        assert_eq!(32, _get_layer_address(&adrs)); // Tree index and layer address "are the same"
    }
}