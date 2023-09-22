#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::time::Instant;
    use floating_duration::TimeFormat;
    use crate::server;
    use rocket::{http::ContentType, http::{ Status}, local::blocking::Client};
    use two_party_ecdsa::curv::arithmetic::traits::Converter;
    use two_party_ecdsa::{party_one};
    use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessage, Party1SecondMessage};
    use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey2, party1};
    use two_party_ecdsa::kms::chain_code::two_party::party2::ChainCode2;

    fn key_gen(client: &Client) -> (String, MasterKey2) {
        let response = client
            .post("/engine/traits/wrap_keygen_first")
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        println!("TEST PUBLIC");
        let res_body = response.into_string().unwrap();

        let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
            serde_json::from_str(&res_body).unwrap();


        let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

        /*************** END: FIRST MESSAGE ***************/

        /*************** START: SECOND MESSAGE ***************/
        let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();
        let response = client
            .post(format!("/engine/traits/{}/wrap_keygen_second", id))
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
            .post(format!("/engine/traits/{}/wrap_keygen_third", id))
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
            .post(format!("/engine/traits/{}/wrap_keygen_fourth", id))
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
            .post(format!("/engine/traits/{}/chaincode/first", id))
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
            .post(format!("/engine/traits/{}/chaincode/second", id))
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

    #[test]
    fn key_gen_and_sign() {
        // Passthrough mode
        env::set_var("region", "");
        env::set_var("pool_id", "");
        env::set_var("issuer", "");
        env::set_var("audience", "");
        // env::set_var("ELASTICACHE_URL", "127.0.0.1");

        let settings = HashMap::<String, String>::from([
            ("db".to_string(), "local".to_string()),
            ("db_name".to_string(), "KeyGenAndSign".to_string()),
        ]);
        let server = server::get_server(settings);
        let client = Client::tracked(server).expect("valid rocket instance");
        let id = key_gen(&client);

        // let message = BigInt::from(1234u32);
        //
        // let signature: party_one::SignatureRecid =
        //     sign(&client, id.clone(), master_key_2, message.clone());
        //
        // println!(
        //     "s = (r: {}, s: {}, recid: {})",
        //     signature.r.to_hex(),
        //     signature.s.to_hex(),
        //     signature.recid
        // );
        // //test v2 sign interface with session id enabled
    }
}
