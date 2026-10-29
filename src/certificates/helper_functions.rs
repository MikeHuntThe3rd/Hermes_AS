use std::{str::FromStr, time::{Duration, UNIX_EPOCH}};

use base64::Engine;
use der::{Encode, asn1::UtcTime};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{Rng, SeedableRng, rngs::{ChaCha12Rng, SysRng}};
use uuid::Uuid;
use x509_cert::{SubjectPublicKeyInfo, builder::{Builder, CertificateBuilder}, name::Name, serial_number::SerialNumber, time::Validity};
use crate::{certificates::{DeviceRegistration, profile_builder::HermesProfile}, responses::error_t::{AuthError, GenericErr, InternalError}, types::{B64_ENGINE, Intermediate, IssuedLeaf, REG_LBL}};

pub struct ValidRegistration { pub verifying_key: VerifyingKey, pub public_key: [u8; 32] }

pub fn validate_registration(user_id: Uuid, req: &DeviceRegistration) -> Result<ValidRegistration, GenericErr> {

    let public_key_bytes = B64_ENGINE.decode(&req.signature_pub_k)
    .map_err(|_| InternalError::DecodeEncodeErr)?;
    let public_key: [u8; 32] = public_key_bytes.try_into()
    .map_err(|_| InternalError::DecodeEncodeErr)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
    .map_err(|_| InternalError::DecodeEncodeErr)?;

    let signature_bytes = B64_ENGINE.decode(&req.proof).map_err(|_| InternalError::DecodeEncodeErr)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| InternalError::DecodeEncodeErr)?;

    let mut msg: Vec<u8> = Vec::with_capacity(REG_LBL.len() + 16 + 32);
    msg.extend_from_slice(REG_LBL);
    msg.extend_from_slice(user_id.as_bytes());
    msg.extend_from_slice(&public_key);

    verifying_key.verify_strict(&msg, &signature)
    .map_err(|_| AuthError::InvalidCredentials)?;

    return Ok(ValidRegistration { verifying_key: verifying_key, public_key: public_key });
}

pub fn issue_leaf(
    imk: &Intermediate, user_id: Uuid, device_id: Uuid,
    verifying_key: &VerifyingKey, now: i64, ttl: i64
) -> Result<IssuedLeaf, InternalError> {
    let not_before = now - 300;
    let not_after = (now + ttl).min(imk.not_after);

    if not_after <= now {
        return Err(InternalError::Invalidlifetime);
    }

    let mut serial: [u8; 16] = [0u8; 16];
    let mut rng = ChaCha12Rng::try_from_rng(&mut SysRng)
    .map_err(|_| InternalError::MiscellaneousInternalError)?;
    rng.fill_bytes(&mut serial);

    let serial_num: SerialNumber<_> = SerialNumber::new(&serial).map_err(|_| InternalError::BadRequest)?;
    let validity: Validity<_> = Validity::new(
        x509_cert::time::Time::UtcTime(UtcTime::from_system_time(UNIX_EPOCH + Duration::from_secs(not_before as u64))
        .map_err(|_| InternalError::DecodeEncodeErr)?),
        x509_cert::time::Time::UtcTime(UtcTime::from_system_time(UNIX_EPOCH + Duration::from_secs(not_after as u64))
        .map_err(|_| InternalError::DecodeEncodeErr)?)
    );

    let spki = SubjectPublicKeyInfo::from_key(&verifying_key.clone())
    .map_err(|_| InternalError::DecodeEncodeErr)?;

    let subject = Name::from_str(&format!("CN={device_id}")).map_err(|_| InternalError::DecodeEncodeErr)?;
    let profile = HermesProfile {
        user_id: user_id,
        device_id: device_id,
        issuer: imk.subject.clone(),
        subject: subject,
    };


    let cert_builder = CertificateBuilder::new(profile, serial_num, validity, spki)
    .map_err(|_| InternalError::DecodeEncodeErr)?;
    let cert = cert_builder.build(&imk.signer).map_err(|_| InternalError::DecodeEncodeErr)?;

    return Ok(IssuedLeaf { 
        leaf_der: cert.to_der().map_err(|_| InternalError::DecodeEncodeErr)?, 
        serial: serial.to_vec(), 
        not_after: not_after, 
        key_id: imk.key_id.clone(), 
        intermediate_der: imk.cert_der.clone() 
    });
}

