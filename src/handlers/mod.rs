// use std::{str::FromStr, time::{Duration, UNIX_EPOCH}};

// use der::asn1::UtcTime;
// use ed25519_dalek::{Signature, VerifyingKey};
// use time::{Duration, Time};
// use uuid::Uuid;
// use x509_cert::{SubjectPublicKeyInfo, builder::CertificateBuilder, certificate::Rfc5280, name::Name, serial_number::SerialNumber, time::Validity};

// use crate::responses::error_t::InternalError;

pub mod post;
pub mod delete;
pub mod patch;
pub mod get;

// pub struct Intermediate {
//     pub key_id: String,            // lowercase hex of SKI
//     pub ski: Vec<u8>,
//     pub cert_der: Vec<u8>,
//     pub subject: x509_cert::name::Name,
//     pub signer: ed25519_dalek::SigningKey,
//     pub not_before: i64,
//     pub not_after: i64,
//     pub active: bool,              // allowed to sign new leaves
// }

// pub struct DeviceReg {
//     pub signature_pub_k: String,
//     pub proof: String,
//     pub device_name: String,
// }

// pub struct IssuedLeaf {
//     pub leaf_der: Vec<u8>,
//     pub serial: Vec<u8>,
//     pub not_after: i64,
//     pub key_id: String,
//     pub intermediate_der: Vec<u8>,
// }

// pub struct Pki { pub intermediates: Vec<Intermediate> }

// impl Pki {
//     pub fn signer_at(&self, now: i64) -> Option<&Intermediate> {
//         self.intermediates.iter()
//             .filter(|i| i.active && i.not_before <= now && now < i.not_after)
//             .max_by_key(|i| i.not_before)
//     }
// }

// const REG_LBL: &[u8] = b"herpesz-api";

// pub struct ValidReg { pub verif_k: VerifyingKey, pub pub_key: [u8; 32] }

// fn validate_reg(user_id: Uuid, req: &DeviceReg) -> Result<ValidReg, InternalError> {
//     use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64_ENGINE};

//     let public_key_bytes = B64_ENGINE.decode(&req.signature_pub_k).map_err(|_| InternalError::BadRequest)?;
//     let public_key: [u8; 32] = public_key_bytes.try_into().map_err(|_| InternalError::BadRequest)?;
//     let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| InternalError::BadRequest)?;

//     let signature_bytes = B64_ENGINE.decode(&req.proof).map_err(|_| InternalError::BadRequest)?;
//     let signature = Signature::from_slice(&signature_bytes).map_err(|_| InternalError::BadRequest)?;

//     let mut msg: Vec<u8> = Vec::with_capacity(REG_LBL.len() + 16 + 32);
//     msg.extend_from_slice(REG_LBL);
//     msg.extend_from_slice(user_id.as_bytes());
//     msg.extend_from_slice(&public_key);

//     verifying_key.verify_strict(&msg, &signature).map_err(|_| InternalError::BadRequest)?;

//     return Ok(ValidReg { verif_k: verifying_key, pub_key: public_key });
// }

// pub fn issue_leaf(
//     inter: &Intermediate, user_id: Uuid, device_id: Uuid,
//     verifying_key: &VerifyingKey, now: i64, ttl: i64
// ) -> Result<IssuedLeaf, InternalError> {
//     let now_before = now - 300;
//     let now_after = now + ttl;
//     //ttl check im not gonna write

//     let mut serial = [0u8; 16];
//     //fill the serial array up with 128 random bits wiuth whatev
//     serial[0] &= 0x7f;

//     let serial_num: SerialNumber<Rfc5280> = SerialNumber::new(&serial).map_err(|_| InternalError::BadRequest)?;
//     let validity: Validity<Rfc5280> = Validity::new(
//         x509_cert::time::Time::UtcTime(UtcTime::from_system_time(UNIX_EPOCH + Duration::from_secs(now_before as u64)).unwrap()),
//         x509_cert::time::Time::UtcTime(UtcTime::from_system_time(UNIX_EPOCH + Duration::from_secs(now_after as u64)).unwrap())
//     );

//     let subject = Name::from_str(&device_id.to_string()).unwrap();
//     let subject_pki = SubjectPublicKeyInfo::from_key().unwrap();

//     let mut cert_builder = CertificateBuilder::<Rfc5280>::new(, serial_num, validity, subject_public_key_info)

//     Err(InternalError::BadRequest)
// }