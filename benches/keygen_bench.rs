use std::collections::HashMap;
use std::env;
use std::time::Instant;
use floating_duration::TimeFormat;
use rocket::{http::ContentType, http::{ Status}, local::blocking::Client};
use two_party_ecdsa::curv::arithmetic::routes::Converter;
use two_party_ecdsa::{party_one};
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessage, Party1SecondMessage};
use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey2, party1};
use two_party_ecdsa::kms::chain_code::two_party::party2::ChainCode2;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use pprof::criterion::{Output, PProfProfiler};
use public_server_lib::server::*;
mod keygen_bench;

fn key_gen(client: &Client) -> (String, MasterKey2) {
    let response = client
        .post("/ecdsa/keygen/wrap_keygen_first")
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    let res_body = response.into_string().unwrap();

    let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
        serde_json::from_str(&res_body).unwrap();


    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    /*************** END: FIRST MESSAGE ***************/

    /*************** START: SECOND MESSAGE ***************/
    let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();
    let response = client
        .post(format!("/ecdsa/keygen/{}/wrap_keygen_second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();
    let kg_party_one_second_message: party1::KeyGenParty1Message2 =
        serde_json::from_str(&res_body).unwrap();


    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );
    assert!(key_gen_second_message.is_ok());


    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    /*************** END: SECOND MESSAGE ***************/

    /*************** START: THIRD MESSAGE ***************/
    let body = serde_json::to_string(&party_two_second_message.pdl_first_message).unwrap();

    let response = client
        .post(format!("/ecdsa/keygen/{}/wrap_keygen_third", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();
    let party_one_third_message: party_one::PDLFirstMessage =
        serde_json::from_str(&res_body).unwrap();

    let start = Instant::now();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    /*************** END: THIRD MESSAGE ***************/

    /*************** START: FOURTH MESSAGE ***************/

    let party_2_pdl_second_message = pdl_decom_party2;
    let request = party_2_pdl_second_message;
    let body = serde_json::to_string(&request).unwrap();


    let response = client
        .post(format!("/ecdsa/keygen/{}/wrap_keygen_fourth", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);



    let res_body = response.into_string().unwrap();
    let party_one_pdl_second_message: party_one::PDLSecondMessage =
        serde_json::from_str(&res_body).unwrap();


    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message,
    )
        .expect("pdl error party1");

    /*************** START: CHAINCODE FIRST MESSAGE ***************/

    let response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/first", id))
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);


    let res_body = response.into_string().unwrap();
    let cc_party_one_first_message: Party1FirstMessage = serde_json::from_str(&res_body).unwrap();

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        ChainCode2::chain_code_first_message();


    /*************** END: CHAINCODE FIRST MESSAGE ***************/

    /*************** START: CHAINCODE SECOND MESSAGE ***************/
    let body = serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();


    let response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();
    let cc_party_one_second_message: Party1SecondMessage = serde_json::from_str(&res_body).unwrap();

    let _cc_party_two_second_message = ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message,
    );


    /*************** END: CHAINCODE SECOND MESSAGE ***************/

    let party2_cc = ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    )
        .chain_code;


    /*************** END: CHAINCODE COMPUTE MESSAGE ***************/



    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    /*************** END: MASTER KEYS MESSAGE ***************/

    (id, party_two_master_key)
}

/// Benchmarks keygen phase from client side invoking gotham server endpoints
pub fn criterion_benchmark(c: &mut Criterion) {
    let settings = HashMap::<String, String>::from([
        ("db".to_string(), "local".to_string()),
        ("db_name".to_string(), "KeyGenAndSign".to_string()),
    ]);
    let server = get_server(settings);
    let client = Client::tracked(server).expect("valid rocket instance");

    c.bench_with_input(
        BenchmarkId::new("keygen_benchmark", 1),
        &client,
        |b, client| {
            b.iter(|| {
                let (_, _): (String, MasterKey2) = key_gen(&client);
            })
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = criterion_benchmark
}
criterion_main!(benches);
