// use halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
// use rand::rngs::OsRng;

// use halo2_proofs::{
//     dev::MockProver,
//     plonk::{
//         create_proof, keygen_pk, keygen_vk, verify_proof, Circuit,
//         ProvingKey, VerifyingKey,
//     },
//     poly::{
//         commitment::{Params, ParamsProver},
//         kzg::{
//             commitment::{KZGCommitmentScheme, ParamsKZG},
//             multiopen::{ProverGWC, VerifierGWC},
//             strategy::AccumulatorStrategy,
//         },
//         VerificationStrategy,
//     },
//     transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
// };
// use snark_verifier::{
//     loader::evm::{self, deploy_and_call, encode_calldata, EvmLoader},
//     pcs::kzg::{Gwc19, KzgAs},
//     system::halo2::{compile, transcript::evm::EvmTranscript, Config},
//     verifier::{self, SnarkVerifier},
// };
// use std::rc::Rc;

// type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;


use halo2_jwt::circuit::JwtCircuit;
use halo2_jwt::precompute::PreComputed;
use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;

// fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
//     ParamsKZG::<Bn256>::setup(k, OsRng)
// }

// fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
//     let vk = keygen_vk(params, circuit).unwrap();
//     keygen_pk(params, vk, circuit).unwrap()
// }

// fn gen_proof<C: Circuit<Fr>>(
//     params: &ParamsKZG<Bn256>,
//     pk: &ProvingKey<G1Affine>,
//     circuit: C,
//     instances: Vec<Vec<Fr>>,
// ) -> Vec<u8> {
//     MockProver::run(params.k(), &circuit, instances.clone())
//         .unwrap()
//         .assert_satisfied();

//     let instances_ref = &instances
//         .iter()
//         .map(|instances| instances.as_slice())
//         .collect::<Vec<_>>();

//     let proof = {
//         let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
//         create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
//             params,
//             pk,
//             &[circuit],
//             &[instances_ref],
//             OsRng,
//             &mut transcript,
//         )
//         .unwrap();
//         transcript.finalize()
//     };

//     let accept = {
//         let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
//         VerificationStrategy::<_, VerifierGWC<_>>::finalize(
//             verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
//                 params.verifier_params(),
//                 pk.get_vk(),
//                 AccumulatorStrategy::new(params.verifier_params()),
//                 &[instances_ref],
//                 &mut transcript,
//             )
//             .unwrap(),
//         )
//     };
//     assert!(accept);

//     proof
// }

// fn gen_evm_verifier(
//     params: &ParamsKZG<Bn256>,
//     vk: &VerifyingKey<G1Affine>,
//     num_instance: Vec<usize>,
// ) -> Vec<u8> {
//     let protocol = compile(
//         params,
//         vk,
//         Config::kzg().with_num_instance(num_instance.clone()),
//     );
//     let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

//     let loader = EvmLoader::new::<Fq, Fr>();
//     let protocol = protocol.loaded(&loader);
//     let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

//     let instances = transcript.load_instances(num_instance);
//     let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
//     PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

//     println!("Yul Code {:?}", loader.yul_code());
//     evm::compile_yul(&loader.yul_code())
// }

// fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
//     let calldata = encode_calldata(&instances, &proof);

//     println!("calldata len {:?}", calldata.len());
//     let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
//     dbg!(gas_cost);
// }

fn main() {
    env_logger::init(); 
    let k = 17;
    // let params = gen_srs(17);

    // Instantiate the circuit with the private inputs.
    let jwt = "{\"iss\":\"https://dev-9h47ajc9.us.au111th0.com/\",\"sub\":\"twitter|337834122\",\"aud\":\"123\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}";
    let credential = "twitter|337834122";

    let precomputed = PreComputed::new(jwt, credential);
    let public_inputs = precomputed.public_inputs();
    let circuit = JwtCircuit::new(precomputed);

    // let pk = gen_pk(&params, &circuit);
    // let deployment_code = gen_evm_verifier(&params, pk.get_vk(), JwtCircuit::num_instance());

    // println!("Deployment Code {:?}", deployment_code.len());
    // let proof = gen_proof(&params, &pk, circuit.clone(), vec![public_inputs.clone()]);
    // evm_verify(deployment_code, vec![public_inputs], proof);

    // Given the correct public input, our circuit will verify.
    let prover: MockProver<Fr> = MockProver::run(k, &circuit, vec![public_inputs]).expect("Circuit Construction Failed");
    assert_eq!(prover.verify(), Ok(()));

    println!("Done!");
}
