/*
 * Copyright 2018-2022 TON DEV SOLUTIONS LTD.
 *
 * Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
 * this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific TON DEV software governing permissions and
 * limitations under the License.
 */
use abi_json::json_abi::{decode_function_response, encode_function_call};
use abi_json::Contract;
use anyhow::{format_err, Result};
use sha2::{Digest, Sha256};
use tvm_types::{ed25519_create_private_key, BuilderData, SliceData};

pub fn build_abi_body(
    abi_file: &str,
    method: &str,
    params: &str,
    header: Option<&str>,
    keypair: Option<ed25519_dalek::Keypair>,
    internal: bool,
    address: Option<String>,
) -> Result<BuilderData> {
    let key = keypair.map(|pair| ed25519_create_private_key(pair.secret.as_bytes()).unwrap());
    let address = address.unwrap_or_default();
    encode_function_call(
        &load_abi_json_string(abi_file)?,
        method,
        header,
        params,
        internal,
        key.as_ref(),
        if address.is_empty() {
            None
        } else {
            Some(address.as_str())
        },
    )
}

pub fn load_abi_json_string(abi_file: &str) -> Result<String> {
    std::fs::read_to_string(abi_file)
        .map_err(|e| format_err!("unable to read ABI file {}: {}", abi_file, e))
}

pub fn load_abi_contract(abi_json: &str) -> Result<Contract> {
    Contract::load(abi_json.as_bytes())
        .map_err(|e| format_err!("cannot parse contract abi: {:?}", e))
}

pub fn decode_body(
    abi_file: &str,
    method: &str,
    body: SliceData,
    internal: bool,
) -> Result<std::string::String, anyhow::Error> {
    decode_function_response(
        &load_abi_json_string(abi_file)?,
        method,
        body,
        internal,
        false,
    )
}
pub fn gen_abi_id(mut abi: Option<Contract>, func_name: &str) -> u32 {
    if let Some(ref mut contract) = abi {
        let functions = contract.functions();
        let events = contract.events();
        functions
            .get(func_name)
            .map(|f| f.get_input_id())
            .or_else(|| events.get(func_name).map(|e| e.get_function_id()))
            .unwrap_or_else(|| calc_func_id(func_name))
    } else {
        calc_func_id(func_name)
    }
}

fn calc_func_id(func_interface: &str) -> u32 {
    let mut id_bytes = [0u8; 4];
    let hash = Sha256::digest(func_interface.as_bytes());
    id_bytes.copy_from_slice(&hash[..4]);
    u32::from_be_bytes(id_bytes)
}
