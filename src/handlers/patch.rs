use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use uuid::Uuid;

use crate::{axum_trait_impls::extractors::AuthUser, responses::error_t::{AuthError, GenericErr, InternalError}, types::{AppState, Res, User}};

#[derive(Deserialize)]
pub struct StrippedUser {
  nickname: String,
  username: String,
  password: String,
  pfp: String,
  home_ds: String
}


pub async fn update_self(
    auth: AuthUser,
    State(mut state): State<AppState>,
    Json(data): Json<StrippedUser>,
) -> Result<Res<()>, GenericErr> {
    if data.nickname.trim().len() < 3 {
        return Err(GenericErr::Auth(AuthError::InvalidNickname));
    }

    if data.username.trim().len() < 3 || data.password.trim().len() < 3 {
        return Err(GenericErr::Internal(
            InternalError::InvalidAccountCredentials,
        ));
    }

    let old_user: User = state
        .pg_interface
        .select_one((&["id"], &[auth.user_id]))
        .await
        .map_err(|_| GenericErr::Internal(InternalError::DbError))?;

    state
        .pg_interface
        .update_one(User {
            id: auth.user_id,
            prv: old_user.prv,
            home_ds: Uuid::new_v4(),
            nickname: data.nickname,
            username: data.username,
            password: data.password,
            pfp: Some(data.pfp),
        })
        .await
        .map_err(|_| GenericErr::Internal(InternalError::DbError))?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}