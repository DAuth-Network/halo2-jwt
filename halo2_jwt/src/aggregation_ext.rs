use halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;

use crate::circuit::JwtCircuit;

impl CircuitExt<Fr> for JwtCircuit {
    
    // number of public inputs
    fn num_instance(&self) -> Vec<usize> {
        vec![18]
    }

    // the public inputs
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.public_inputs()]
    }
}