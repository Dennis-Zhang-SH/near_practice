use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::near_bindgen;
use rs_merkle::{algorithms::Sha256, MerkleProof, MerkleTree};

near_sdk::setup_alloc!();

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct SimpleSmartContract {
    tree: LookupMap<String, Vec<[u8; 32]>>,
}

impl Default for SimpleSmartContract {
    fn default() -> Self {
        Self {
            tree: LookupMap::new(b"tree".to_vec()),
        }
    }
}

#[near_bindgen]
impl SimpleSmartContract {
    pub fn verify(&self, digest: Vec<u8>) -> bool {
        if digest.len() != 32 {
            return false;
        }
        let arr: [u8; 32] = digest.try_into().unwrap();
        let tree = self.tree.get(&String::from("tree"));
        match tree {
            Some(v) => {
                let tree = MerkleTree::<Sha256>::from_leaves(&v);
                for i in 0..v.len() {
                    let indices_proof = vec![i];
                    let merkle_proof = tree.proof(&indices_proof);
                    let merkle_root = match tree.root() {
                        Some(r) => r,
                        _ => return false,
                    };
                    let proof = match MerkleProof::<Sha256>::try_from(merkle_proof.to_bytes()) {
                        Ok(p) => p,
                        _ => return false,
                    };
                    if proof.verify(merkle_root, &indices_proof, &vec![arr], v.len()) {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    pub fn update(&mut self, merkle_tree: Vec<u8>) {
        let converted = convert_to_array(merkle_tree).unwrap();
        self.tree.insert(&"tree".to_owned(), &converted);
    }
}

fn convert_to_array(v: Vec<u8>) -> Result<Vec<[u8; 32]>, &'static str> {
    if v.len() / 32 != 0 {
        return Err("Not in sha256 format");
    }
    let (len, cap) = (v.len() / 32, v.capacity() / 32);
    let boxed = Box::leak(v.into_boxed_slice()) as *mut [u8] as *mut [u8; 32];
    unsafe {
        let v = Vec::from_raw_parts(boxed, len, cap);
        Ok(v)
    }
}
