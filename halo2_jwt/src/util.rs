use halo2_proofs::circuit::Value;
use crate::sha256::BlockWord;

pub fn pad_bytes_front_n_end(origin: &[u8], front_pad: usize, end_pad: usize) -> Vec<u8> {
    let mut result = Vec::new();
    for _ in 0..front_pad {
        result.push(0u8);
    }

    for i in origin {
        result.push(* i);
    }

    for _ in 0..end_pad {
        result.push(0u8);
    }

    result
}

pub fn usize_to_bytes(size: usize) -> [u8; 8] {
    let mut result = [0u8; 8];
    let mut remain = size;
    for o in 1..9 {
        result[8 - o] = (remain % 256) as u8;
        remain /= 256;
    }

    result
}

pub fn pad_sha256_bytes(origin: &[u8]) -> Vec<u8> {
    let len = origin.len();
    let plen = len + 1 + 8; // one 0x80 and 4 bytes len
    
    let blocks = (plen + 63) >> 6;

    let mut result = Vec::new();

    // 1. first - push in all items
    for item in origin {
        result.push(* item);
    }

    // 2. push a 0x80
    result.push(0x80);

    // 3. calculate how many bytes of zero should we push 
    for _ in 0..(64 * blocks - plen) {
        result.push(0);
    }

    // 4. push in the len
    let len_u8 = usize_to_bytes(len * 8);

    for len_byte in len_u8 {
        result.push(len_byte);
    }

    result

}

pub fn bytes_to_u32(origin: &[u8]) -> u32 {
    let origin_len = origin.len();

    let mut acc = 0;
    for offset in 0..origin_len {
        acc += (origin[offset] as u32) << ((origin_len - offset - 1) * 8);
    }

    if origin_len < 4 {
        acc = acc << (4 - origin_len) * 8;
    }
    acc
}

pub fn bytes_to_u32_array(origin: &[u8]) -> Vec<u32> {
    let len = origin.len();
    let mut offset = 0;
    
    let mut result: Vec<u32> = Vec::new();
    loop {
        if offset + 4 > len {
            break;
        } else if offset + 4 > len {
            result.push(
                bytes_to_u32(&origin[offset..len])
            );
            break;
        } else {
            result.push(
                bytes_to_u32(&origin[offset..offset + 4])
            );
            offset += 4;
        }
    }

    result
}

pub fn u32_array_to_blockwords(origin: &[u32]) -> Vec<BlockWord> {
    let len = origin.len();
    assert!(len % 8 == 0);

    origin
        .iter()
        .map(|n| BlockWord(Value::known(*n)))
        .collect()
}

pub fn find_subsequence_u8(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn sha256_hash_bytes_digests(msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();

    digest.into()
}