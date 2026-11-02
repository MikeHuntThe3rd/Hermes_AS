use axum::{extract::{Path, State}, http::{StatusCode}};
use base64::Engine;
use der::Decode;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use x509_cert::Certificate;

use crate::{axum_trait_impls::extractors::AuthUser, responses::error_t::InternalError, types::{AppState, B64_ENGINE, BindVal::ID, Device, Res, User}};

#[derive(Serialize)]
pub struct IntermediateKeys {
    pub key_id: String,
    pub public_key: String,
    pub not_before: i64,
    pub not_after: i64,
    pub root_signature: String
}

#[derive(Serialize)]
pub struct UserProfile {
    user_id: Uuid,
    nickname: String,
    pfp: Option<String>,
    home_ds: Uuid
}

#[derive(Serialize)]
pub struct Devices {
    device_id: Uuid,
    user_id: Uuid,
    sig_pubkey: String,
    created_at: i64,
    revoked: bool
}

#[derive(Serialize)]
pub struct DeviceElement {
    pub device_id: Uuid,
    pub sig_pubkey: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct SignedDeviceList {
    pub user_id: Uuid,
    pub version: i64,
    pub devices: Vec<DeviceElement>,
    pub iat: i64,
    pub key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct Jwks {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: Uuid,
    pub alg: String,
    #[serde(rename = "use")]
    pub usage: String
}

pub async fn get_user_profile(
    auth: AuthUser,
    State(mut state): State<AppState>, 
    Path(user_id): Path<Uuid>)  -> Result<Res<UserProfile>, InternalError> {
    let user: User = state.pg_interface.select_one((&["id"], &[user_id])).await?;

    return Ok(Res { status: StatusCode::OK, success: true, msg: String::new(), data: Some(UserProfile {
        user_id: user.id,
        nickname: user.nickname,
        pfp: user.pfp,
        home_ds: user.home_ds
    }) });
}

pub async fn get_devices(
    auth: AuthUser, 
    State(mut state): State<AppState>
) -> Result<Res<Vec<Devices>>, InternalError> {
    let devices: Vec<Device> = state.pg_interface.select_many(Some((&["user_id"], &[auth.user_id])), None)
    .await?;

    let res_devices: Vec<Devices> = devices.into_iter().map(|device| {
        let cat = device.id.get_timestamp()
            .ok_or(InternalError::DecodeEncodeErr)?.to_unix().0 as i64;

        return Ok(Devices {
            device_id: device.id,
            user_id: device.user_id,
            sig_pubkey: B64_ENGINE.encode(device.sig_pubkey),
            created_at: cat,
            revoked: device.is_revoked
        });
    }).collect::<Result<Vec<Devices>, InternalError>>()?;

    return Ok(Res 
        { status: StatusCode::OK, 
            success: true, 
            msg: String::new(),
            data: Some(res_devices) });
}

pub async fn get_signed_devices(
    _auth: AuthUser, 
    State(mut state): State<AppState>,
    Path(user_id): Path<Uuid>
) -> Result<Res<SignedDeviceList>, InternalError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let imk = state.pki
    .get_im_key(now).ok_or(InternalError::NoMatches)?;

    let devices: Vec<Device> = state
        .pg_interface.select_many(Some((&["user_id"], &[user_id])), None)
        .await?;

    let user: User = state.pg_interface.select_one((&["id"], &[user_id])).await?;

    let devices_elements = devices.into_iter().map(|device| {
        let cat = device.id.get_timestamp()
            .ok_or(InternalError::DecodeEncodeErr)?.to_unix().0 as i64;

        return Ok(DeviceElement {
            device_id: device.id,
            sig_pubkey: B64_ENGINE.encode(device.sig_pubkey),
            created_at: cat
        });
    }).collect::<Result<Vec<DeviceElement>, InternalError>>()?;

    let mut res_list = SignedDeviceList {
        user_id: user_id,
        version: user.changes,
        devices: devices_elements,
        iat: now,
        key_id: imk.key_id.clone(),
        signature: String::new(),
    };

    let mut json_object = serde_json::to_value(&res_list).map_err(|_| InternalError::DecodeEncodeErr)?;
    
    json_object.as_object_mut().ok_or(InternalError::DecodeEncodeErr)?
    .remove("signature").ok_or(InternalError::DecodeEncodeErr)?;

    let bytes = serde_jcs::to_vec(&json_object)
    .map_err(|_| InternalError::DecodeEncodeErr)?;

    res_list.signature = B64_ENGINE.encode(imk.signer.sign(&bytes).to_bytes());

    return Ok(Res { 
        status: StatusCode::OK, 
        success: true, 
        msg: String::new(), 
        data: Some(res_list) 
    });
}

pub async fn get_intermediate_keys(
    _auth: AuthUser,
    State(state): State<AppState>
) -> Result<Res<Vec<IntermediateKeys>>, InternalError> {
    
    let mut res_imks: Vec<IntermediateKeys> = Vec::with_capacity(state.pki.intermediates.len());

    for imk in &*state.pki.intermediates {
        let cert = Certificate::from_der(&imk.cert_der)
        .map_err(|_| InternalError::DecodeEncodeErr)?;
        
        let pubk_bstring = &cert.tbs_certificate().subject_public_key_info()
        .subject_public_key;

        let pubk = VerifyingKey::from_bytes(
            pubk_bstring.as_bytes().ok_or(InternalError::DecodeEncodeErr)?
            .try_into().map_err(|_| InternalError::DecodeEncodeErr)?
        )
        .map_err(|_| InternalError::DecodeEncodeErr)?;

        //TODO: NOT VALIDATED(verify_strict) YET DO THAT LATER
        let sig = Signature::from_bytes(
            cert.signature().as_bytes().ok_or(InternalError::DecodeEncodeErr)?
            .try_into().map_err(|_| InternalError::DecodeEncodeErr)?
        );

        let im = IntermediateKeys {
            key_id: imk.key_id.clone(),
            public_key: B64_ENGINE.encode(pubk.as_bytes()),
            not_before: imk.not_before,
            not_after: imk.not_after,
            root_signature: B64_ENGINE.encode(sig.to_bytes()),
        };

        res_imks.push(im);
    }

    return Ok(Res { 
        status: StatusCode::OK, 
        success: true, 
        msg: String::new(), 
        data: Some( res_imks )
    });
}

pub async fn get_jwt_okp_keys(
    _auth: AuthUser,
    State(state): State<AppState>
) -> Result<Res<Jwks>, InternalError> {
    return Ok(Res { status: StatusCode::OK, success: true, msg: String::new(), data: Some(
        Jwks {
            kty: state.jwt_okp.kty.clone(),
            crv: state.jwt_okp.crv.clone(),
            x: B64_ENGINE.encode(state.jwt_okp.signer.verifying_key().as_bytes()),
            kid: state.jwt_okp.kid.clone(),
            alg: state.jwt_okp.alg.clone(),
            usage: state.jwt_okp.usage.clone(),
        }
    ) });
}

pub async fn get_users_by_username(
    _auth: AuthUser,
    State(mut state): State<AppState>,
    Path(nickname): Path<String>
) -> Result<Res<Vec<UserProfile>>, InternalError>{
    let all_users: Vec<UserProfile> = state.pg_interface.select_many::<i8, User>(None, None)
    .await?.into_iter()
    .map(|user| UserProfile{user_id:user.id, nickname:user.nickname, pfp:user.pfp, home_ds:user.home_ds})
    .collect();

    let mut searched_users: Vec<UserProfile> = Vec::new();
    for user in all_users{
        if user.nickname == nickname{
            searched_users.push(user);
        }
    }

    return Ok(Res {status: StatusCode::OK, success:true, msg: String::new(), data: Some(
        searched_users
    )});
}