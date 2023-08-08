use halo2curves::pasta::{pallas, Fp};

use crate::sha256::BlockWord;
use crate::util::{find_subsequence_u8, pad_bytes_front_n_end, sha256_hash_bytes_digests, pad_sha256_bytes, bytes_to_u32_array, u32_array_to_blockwords};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreComputed {
    jwt_bytes: Vec<u8>,
    original_credential_bytes: Vec<u8>,
    credential_bytes: Vec<u8>,

    segment_location_start: usize,
    segment_location_end: usize,
    segment_start_offset: usize,
    segment_end_offset: usize,

    digest_jwt: [u8; 32],
    digest_credential: [u8; 32],
}

impl PreComputed {
    pub fn new(jwt: &str, credential: &str) -> Self {
        let jwt = jwt.as_bytes();
        let credential = credential.as_bytes();

        Self::new_with_bytes(jwt, credential)
    }

    pub fn new_with_bytes(jwt: &[u8], credential: &[u8]) -> Self {
        let credential_len = credential.len();

        let byte_position = find_subsequence_u8(jwt, credential)
            .expect("credential to be contained within the JWT");

        let segment_location_start = byte_position / 4;
        let segment_location_end = (byte_position + credential_len) / 4;
        let segment_start_offset = byte_position % 4;
        let segment_end_offset = (byte_position + credential_len) % 4;

        let padded_credential = pad_bytes_front_n_end(credential, segment_start_offset, segment_end_offset);

        Self {
            jwt_bytes: jwt.to_vec(),
            original_credential_bytes: credential.to_vec(),
            credential_bytes: padded_credential.to_vec(),

            segment_location_start, segment_location_end,
            segment_start_offset, segment_end_offset,

            digest_jwt: sha256_hash_bytes_digests(&jwt),
            digest_credential: sha256_hash_bytes_digests(&padded_credential),
        }
    }

    pub fn preimage_as_blockwords(&self) -> [Vec<BlockWord>; 2] {
        let padded_message_jwt = pad_sha256_bytes(&self.jwt_bytes);
        let padded_message_credential = pad_sha256_bytes(&self.credential_bytes);

        let u32_padded_jwt = bytes_to_u32_array(&padded_message_jwt, 0);
        let u32_padded_credential = bytes_to_u32_array(&padded_message_credential, 0);

        [
            u32_array_to_blockwords(&u32_padded_jwt),
            u32_array_to_blockwords(&u32_padded_credential),
        ]
    }

    pub fn expected_digest_as_blockwords(&self) -> [Vec<BlockWord>; 2] {
        let digest_jwt = bytes_to_u32_array(&self.digest_jwt, 0);
        let digest_credential = bytes_to_u32_array(&self.digest_credential, 0);

        [
            u32_array_to_blockwords(&digest_jwt),
            u32_array_to_blockwords(&digest_credential),
        ]
    }

    pub fn public_inputs(&self) -> Vec<Fp> {
        let mut result = Vec::with_capacity(16);
        let digest_jwt_u32 = bytes_to_u32_array(&self.digest_jwt, 0);
        let digest_credential_u32 = bytes_to_u32_array(&self.digest_credential, 0);

        for i in 0..8 {
            result.push(pallas::Base::from(digest_jwt_u32[i] as u64));
        }

        for i in 0..8 {
            result.push(pallas::Base::from(digest_credential_u32[i] as u64));
        }

        result.push(pallas::Base::from(self.segment_start_offset as u64));
        result.push(pallas::Base::from(self.segment_end_offset as u64));

        result
    }
    
    pub fn segment_location(&self) -> (usize, usize) {
        (self.segment_location_start, self.segment_location_end)
    }

    pub fn segment_offset(&self) -> (usize, usize) {
        (self.segment_start_offset, self.segment_end_offset)
    }

    pub fn log_all(&self) {
        log::info!("[Pre-Constrained] JWT Len: {:?} Credential Len: {:?} Credential Padded Len {:?}", self.jwt_bytes.len(), self.original_credential_bytes.len(), self.credential_bytes.len());
        log::debug!("[Pre-Constrained] JWT Hash: {:?} Credential Hash: {:?}", self.digest_jwt, self.digest_credential);
        log::info!("[Pre-Constrained] Segment Start: {:?} Segment End: {:?}", self.segment_location_start, self.segment_location_end);
        log::info!("[Pre-Constrained] Segment Start Offset: {:?} Segment End Offset: {:?}", self.segment_start_offset, self.segment_end_offset);
    }
}

#[test]
fn e2e_precompute_test() {
    let a = [
        0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08, 
        0x9, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16,
        0x17, 0x18,
    ];
    let b = [
                    0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x10
    ];
    let precompute = PreComputed::new_with_bytes(&a, &b);

    println!("{:?}", precompute.credential_bytes);
}
