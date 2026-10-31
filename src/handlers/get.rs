use axum::{extract::{Path, State}, http::StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{axum_trait_impls::extractors::AuthUser, responses::error_t::InternalError, types::{AppState, B64_ENGINE, Device, Res, User}};

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