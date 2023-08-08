use halo2_jwt::circuit::JwtCircuit;
use halo2_jwt::precompute::PreComputed;

fn main() {
    use halo2_proofs::dev::MockProver;

    env_logger::init(); 
    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 18;

    // Instantiate the circuit with the private inputs.

    let jwt = "{\"iss\":\"https://dev-9h47ajc9.us.au111th0.com/\",\"sub\":\"twitter|337834122\",\"aud\":\"123\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}";
    // let jwt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatwitter|337834122aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let credential = "twitter|337834122";


    // let jwt = "123456";
    // let credential = "23";

    let precomputed = PreComputed::new(jwt, credential);
    let public_inputs = precomputed.public_inputs();
    let circuit = JwtCircuit::new(precomputed);

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).expect("Circuit Construction Failed");

    // println!("{:?}", prover.err());
    assert_eq!(prover.verify(), Ok(()));

    println!("Done!");
}
