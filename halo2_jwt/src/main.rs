use std::path::Path;

use halo2_jwt::circuit::JwtCircuit;
use halo2_jwt::precompute::PreComputed;

use halo2_proofs::dev::MockProver;

use snark_verifier_sdk::{SHPLONK, gen_pk};
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::halo2::{gen_srs, gen_snark_shplonk};
use ark_std::{end_timer, start_timer};

fn main() {
    env_logger::init(); 
    let k_app = 17;
    let k_agg = 22;

    /* START: Setup the circuit & local pre-computed data */
    let jwt = "{\"iss\":\"https://dev-9h47ajc9.us.au111th0.com/\",\"sub\":\"twitter|337834122\",\"aud\":\"123\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}";
    let credential = "twitter|337834122";

    let precomputed = PreComputed::new(jwt, credential);
    let public_inputs = precomputed.public_inputs();
    let circuit = JwtCircuit::new(precomputed);

    // pre-run check
    MockProver::run(k_app, &circuit.clone(), vec![public_inputs])
        .expect("Circuit Construction Failed")
        .assert_satisfied();
    log::info!("JWT circuit Pre-flight check passed. Ready to go.");
    /* END: Setup the circuit & local pre-computed data */

    /* START: Setup SRS + Generate pk & vk */
    // 0. output paths
    let app_pk_path = Path::new("./artifacts/app.pk");
    let app_snark_path = Path::new("./artifacts/app.snark");
    let agg_pk_path = Path::new("./artifacts/agg.pk");
    let agg_snark_path = Path::new("./artifacts/agg.snark");

    // 1. generate params
    let params_app = gen_srs(k_app);
    let params_agg = gen_srs(k_agg);
    log::info!("SRS Parameter generated or readed");

    // 2. generate application pk & snark
    let app_snark_gen_timer = start_timer!(|| "app_snark_gen");
    let pk_app = gen_pk(&params_app, &circuit, Some(app_pk_path));
    let snark_app = gen_snark_shplonk(&params_app, &pk_app, circuit, Some(app_snark_path));
    end_timer!(app_snark_gen_timer);
    log::info!("Application pk & snark generated");

    // 3. generate aggreation pk & snark
    let aggregation_circuit = AggregationCircuit::<SHPLONK>::new(&params_agg, vec![snark_app]);
    
    let agg_snark_gen_timer = start_timer!(|| "agg_snark_gen");
    let agg_pk = gen_pk(&params_agg, &aggregation_circuit, Some(agg_pk_path));
    
    // remove previously generated snark - let's start fresh
    std::fs::remove_file(agg_snark_path).unwrap_or_default();
    let _agg_snark = gen_snark_shplonk(&params_agg, &agg_pk, aggregation_circuit, Some(agg_snark_path));
    end_timer!(agg_snark_gen_timer);
    log::info!("Aggregation pk & snark generated");
    /* END: Setup SRS + Generate pk & vk */

    println!("Done!");
}
