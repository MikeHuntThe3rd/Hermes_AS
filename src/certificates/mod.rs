use serde::Deserialize;

pub mod intermediate_keys;
pub mod helper_functions;
pub mod profile_builder;

#[derive(Deserialize)]
pub struct DeviceRegistration {
    pub signature_pub_k: String,
    pub proof: String,
    pub device_name: String,
}