//!Public gotham implementation
use gotham_engine::traits::*;
use gotham_engine::types::*;
use rocket::async_trait;
use std::collections::HashMap;
use two_party_ecdsa::party_one::Value;
use gotham_engine::types::DatabaseError;
use std::string::String;
use gotham_engine::keygen::KeyGen;

pub struct PublicGotham {
    db_type: DbConnector,
    auth: Authenticator,
    rocksdb_client: rocksdb::DB,
}

pub struct Config {
    pub db: DB,
}

pub enum DB {
    Local(rocksdb::DB),
}

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}

impl PublicGotham {
    pub fn new() -> Self {
        let settings = get_settings_as_map();
        let db_name = settings.get("db_name").unwrap_or(&"db".to_string()).clone();
        if !db_name.chars().all(|e| char::is_ascii_alphanumeric(&e)) {
            panic!("DB name is illegal, may only contain alphanumeric characters");
        }
        let rocksdb_client = rocksdb::DB::open_default(format!("./{}", db_name)).unwrap();

        PublicGotham {
            db_type: DbConnector::RocksDB,
            auth: Authenticator::None,
            rocksdb_client,
        }
    }
}

impl KeyGen for PublicGotham {}

impl Sign for PublicGotham {}

fn idify(user_id: String, id: String, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}

#[async_trait]
impl Db for PublicGotham {
    async fn insert(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), DatabaseError> {
        let identifier = idify(key.clone().customer_id, key.clone().id, table_name);
        // let val_json = serde_json::to_string(value);
        let v_string = serde_json::to_string(&value).unwrap();
        // println!("Insert to RocksDB : {:?}", v_string.clone());

        // let mut prefix: String = "{".to_owned();
        // let preformat = &v_string[v_string.find(':').unwrap()..v_string.len()-1];
        // let format = prefix+&preformat[2..preformat.len()];
        // // let final = format.clone()[..format.clone().len()-1];

        let _ = self.rocksdb_client.put(identifier, v_string.clone());
        Ok(())
    }

    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn Value>>, DatabaseError> {
        let identifier = idify(key.clone().customer_id, key.clone().id, table_name);
        // debug!("Getting from db ({})", identifier);
        let result = self.rocksdb_client.get(identifier.clone()).unwrap();
        let vec_option: Option<Vec<u8>> = result.map(|v| v.to_vec());
        match vec_option {
            Some(vec) => {

                // let mut prefix:String = "{\"".to_owned();
                let val: String = String::from_utf8(vec.clone()).unwrap();
                // println!("result from get = {:?}", val.clone());

                // let preformat = &val[val.find(',').unwrap()..];
                //
                // let format = prefix +&preformat[2..preformat.len()];
                //
                // println!("result from get = {:?}", format.clone());

                let final_val: Box<dyn Value> = serde_json::from_str(String::from_utf8(vec.clone()).expect("Found invalid UTF-8").as_str()).unwrap();
                Ok(Option::from(final_val))
            }
            None => Ok(None),
        }
    }
    async fn has_active_share(&self, user_id: &str) -> Result<bool, String> {
        Ok(false)
    }
}
