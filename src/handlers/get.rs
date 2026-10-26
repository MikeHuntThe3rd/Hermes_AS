use axum::{extract::{Path, State}, http::StatusCode};
use serde::Serialize;
use uuid::Uuid;

use crate::{axum_trait_impls::extractors::AuthUser, responses::error_t::InternalError, types::{AppState, Res, User}};

#[derive(Serialize)]
pub struct UserProfile {
    user_id: Uuid,
    nickname: String,
    pfp: Option<String>,
    home_ds: Uuid
}

pub async fn Get_user_profile(
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