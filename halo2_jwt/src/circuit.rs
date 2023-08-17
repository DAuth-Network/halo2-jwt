use halo2_maingate::{MainGateConfig, MainGate, MainGateInstructions, RegionCtx};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::bn256::Fr;

use crate::precompute::PreComputed;
use crate::sha256::{Table16Config, Table16Chip, Sha256};

#[derive(Debug, Clone)]
pub struct JwtCircuitConfig {
    // contains only the Table16 chip
    pub sha256_config: Table16Config,

    // inclusion proof config 
    pub maingate_config: MainGateConfig,
}

#[derive(Debug, Clone, Default)]
pub struct JwtCircuit {
    precomputed: PreComputed,
}

impl JwtCircuit {
    pub fn new(precomputed: PreComputed) -> Self {
        Self { precomputed }
    }

    pub fn num_instance() -> Vec<usize> {
        vec![18]
    }
}

impl Circuit<Fr> for JwtCircuit {

    type Config = JwtCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::Config {
            sha256_config: Table16Chip::configure(meta), 
            maingate_config: MainGate::<Fr>::configure(meta),
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {

        /* START Pre-Constrained Zone */
        let [preimage_jwt, preimage_credential] = self.precomputed.preimage_as_blockwords();
        let [expected_digest_jwt, expected_digest_credential] = self.precomputed.expected_digest_as_blockwords();
        let (segment_location_start, segment_location_end) = self.precomputed.segment_location();
        let (segment_start_offset, segment_end_offset) = self.precomputed.segment_offset();

        self.precomputed.log_all();
        /* END Pre-Constrained Zone */

        /* START In-Constrained Zone */
        // 1. Load the SHA256 Chip (halo2_gadgets) + MainGate Chip(halo2wrong)
        let sha256_chip = Table16Chip::construct(config.sha256_config.clone());
        Table16Chip::load(config.sha256_config.clone(), &mut layouter.namespace(|| "table16_chip"))?;

        let gate = MainGate::<Fr>::new(config.maingate_config.clone());
        // digest + IV = expected_digest
        let partial_digest_jwt = Sha256::digest(
            sha256_chip.clone(), 
            layouter.namespace(|| "sha256_jwt"), 
            &preimage_jwt
        )?;

        let partial_digest_credential = Sha256::digest(
            sha256_chip, 
            layouter.namespace(|| "sha256_credential"), 
            &preimage_credential
        )?;

        // 2. conduct the inclusion proof
        let (
            expected_digest_jwt_value, 
            expected_digest_credential_value,
            start_offset,
            end_offset,
        ) = layouter.namespace(|| "full_proof").assign_region(|| "full proof", |region| {

            let offset = 0;
            let ctx = &mut RegionCtx::new(region, offset);

            // INCLUSION PROOF
            let (start_offset, end_offset) = {
                // STARTING SEGMENT
                if segment_start_offset != 0 {
                    // JWT 0x1 0x2 0x3 0x4 & Credential 0x00 0x00 0x03 0x04

                    // 1. load both JWTand Credential value into the constrain sys
                    let jwt_value = gate.assign_value(ctx,
                        preimage_jwt[segment_location_start].0
                            .map(|x| Fr::from(x as u64))
                    )?;

                    let credential_value = gate.assign_value(ctx,
                        preimage_credential[0].0
                            .map(|x| Fr::from(x as u64))
                    )?;

                    // 2. sub JWT to Credential -> to get 0x0102_0000 and convert to be_bits
                    let sub = gate.sub(ctx, &jwt_value, &credential_value)?;
                    let sub_bits = gate.to_bits(ctx, &sub, 32)?;

                    assert_eq!(sub_bits.len(), 32);
                    // Numbers of Ending Zero = segment_start_offset * 2
                    // Numbers of Ending Bits in Zero = Segment_start_offset * 8
                    for bit_index in 0..segment_start_offset * 8 {
                        gate.assert_zero(ctx, &sub_bits[bit_index])?;
                    }
                }

                let mut segment_offset = 1;
                loop {
                    // we break early - to correctly handle the end
                    if segment_location_start + segment_offset >= segment_location_end {
                        break;
                    }

                    let jwt_value = gate.assign_value(ctx, 
                        preimage_jwt[segment_location_start + segment_offset].0
                        .map(|x| Fr::from(x as u64)))?;
                    let credential_value = gate.assign_value(ctx, 
                        preimage_credential[segment_offset].0
                        .map(|x| Fr::from(x as u64)))?;


                    log::info!("{:?} {:?} {:?}", segment_offset, jwt_value, credential_value);
                    gate.assert_equal(ctx,  &jwt_value, &credential_value)?;

                    segment_offset += 1;
                }

                // ENDING SEGMENT
                if segment_end_offset != 0 {
                    // JWT 0x1 0x2 0x3 0x4 & Credential 0x10 0x20 0x00 0x00

                    let jwt_value = gate.assign_value(ctx,
                        preimage_jwt[segment_location_end].0
                            .map(|x| Fr::from(x as u64))
                    )?;

                    let credential_value = gate.assign_value(ctx,
                        preimage_credential[segment_offset].0
                            .map(|x| Fr::from(x as u64))
                    )?;

                   // 2. sub JWT to Credential -> to get 0x0000_0304 and convert to be_bits
                   let sub = gate.sub(ctx, &jwt_value, &credential_value)?;
                   let sub_bits = gate.to_bits(ctx, &sub, 32)?;

                   assert_eq!(sub_bits.len(), 32);

                   // Numbers of Leading Zero = segment_end_offset * 2
                   // Numbers of Leading Bits in Zero = segment_end_offset * 8
                   for bit_index in segment_end_offset * 8..32{
                       gate.assert_zero(ctx, &sub_bits[bit_index])?;
                   }
                }

                // assign segment_location_start and segment_location_end to the constrain 
                // awaiting to be exposed as public inputs
                (
                    gate.assign_value(ctx, Value::known(Fr::from(segment_start_offset as u64)))?,
                    gate.assign_value(ctx, Value::known(Fr::from(segment_end_offset as u64)))?
                )
            };

            // SHA256 PROOF
            let (expected_digest_jwt_value, expected_digest_credential_value) = {

                // We would record the loaded digest cell .. so that they could be exposed to public
                let mut expected_digest_jwt_value = Vec::with_capacity(8);
                let mut expected_digest_credential_value = Vec::with_capacity(8);

                // https://stepansnigirev.github.io/visual-sha256/
                for index in 0..8 {
                    log::info!("[Constrained] Iterating SHA256 Proof at Loc {:?}", index);

                    // 1. assign digest to proof
                    let partial_digest_jwt = gate.assign_value(ctx, partial_digest_jwt.0[index].0.map(|x| Fr::from(x as u64)))?;
                    let partial_digest_credential = gate.assign_value(ctx, partial_digest_credential.0[index].0.map(|x| Fr::from(x as u64)))?;

                    // 2. assign expected digest 
                    let expected_digest_jwt = gate.assign_value(ctx, expected_digest_jwt[index].0.map(|x| Fr::from(x as u64)))?;
                    let expected_digest_credential = gate.assign_value(ctx, expected_digest_credential[index].0.map(|x| Fr::from(x as u64)))?;

                    // 3. compare
                    gate.assert_equal(ctx, &partial_digest_jwt, &expected_digest_jwt)?;
                    gate.assert_equal(ctx, &partial_digest_credential, &expected_digest_credential)?;
                    
                    expected_digest_jwt_value.push(expected_digest_jwt);
                    expected_digest_credential_value.push(expected_digest_credential);
                }

                (expected_digest_jwt_value, expected_digest_credential_value)
            };

            Ok((expected_digest_jwt_value, expected_digest_credential_value, start_offset, end_offset))
        })?;

        for i in 0..8 {
            log::info!("[Constrained] Exposing SHA256 as Public Inputs at Loc {:?}", i);

            gate.expose_public(layouter.namespace(|| "public_jwt_digest"), expected_digest_jwt_value[i].clone(), i)?;
            gate.expose_public(layouter.namespace(|| "public_credential_digest"), expected_digest_credential_value[i].clone(), i + 8)?;
        } 

        gate.expose_public(layouter.namespace(|| "public_segment_start_offset"), start_offset, 16)?;
        gate.expose_public(layouter.namespace(|| "public_segment_end_offset"), end_offset, 17)?;
        /* END In-Constrained Zone */

        log::info!("[END] Circuit & Witness Table Generated!");
        Ok(())
    }
}
