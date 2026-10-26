use axum::{Json, extract::State, http::StatusCode};
use fred::interfaces::KeysInterface;
use jsonwebtoken::{DecodingKey, Validation, decode};
use crate::{axum_trait_impls::extractors::{AuthInvite, AuthUser}, responses::error_t::*};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{axum_trait_impls::creation::encode_to_jwt, responses::error_t::GenericErr, types::*};

#[derive(Serialize, Deserialize)]
pub struct UserTokenObj {
    pub user_data: User,
    pub token_data: TokenPair,
}

#[derive(Deserialize)]
pub struct PrivLevel {
    pub prv_level: PrivilegeT,
}

#[derive(Serialize, Deserialize)]
pub struct SingleJwtObj {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenPair {
    pub access_tkn: String,
    pub refresh_tkn: String,
}

#[derive(Serialize, Deserialize)]
pub struct DsCreds {
    pub ds_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Deserialize)]
pub struct LoginCred {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct DeviceCreateInfo {
    pub public_key: String,
    pub device_name: String,
}

#[derive(Deserialize)]
pub struct SignupCred {
    pub nickname: String,
    pub username: String,
    pub password: String,
}

pub async fn login(
    State(mut state): State<AppState>,
    Json(data): Json<LoginCred>,
) -> Result<Res<UserTokenObj>, GenericErr> {
    let user: User = state
        .pg_interface
        .select_one((
            &vec!["username", "password"],
            &vec![&data.username, &data.password],
        ))
        .await
        .map_err(|_| GenericErr::Auth(AuthError::InvalidCredentials))?;

    if user.username == data.username && user.password == data.password {
        let now_utc = OffsetDateTime::now_utc();

        let refersh_uuid = Uuid::new_v4();

        let access = encode_to_jwt(AuthClaims {
            sub: user.id,
            jti: Uuid::new_v4(),
            rjti: Some(refersh_uuid),
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
            tkn_type: TokenType::Access,
        }, &state.secret_b_array)
            .await
            .map_err(|e| GenericErr::Internal(e))?;
        
        let refresh = encode_to_jwt(AuthClaims {
            sub: user.id,
            jti: Uuid::new_v4(),
            rjti: None,
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::days(3)).unix_timestamp() as u64,
            tkn_type: TokenType::Refresh,
        }, &state.secret_b_array)
            .await
            .map_err(|e| GenericErr::Internal(e))?;

        let dta = UserTokenObj {
            user_data: user,
            token_data: TokenPair {
                access_tkn: access,
                refresh_tkn: refresh,
            },
        };

        return Ok(Res {
            status: StatusCode::OK,
            success: true,
            msg: String::new(),
            data: Some(dta),
        });
    } else {
        return Err(GenericErr::Auth(AuthError::InvalidCredentials));
    }
}

pub async fn refresh(
    State(mut state): State<AppState>,
    Json(data): Json<SingleJwtObj>,
) -> Result<Res<TokenPair>, GenericErr> {
    let tkn_data = decode::<AuthClaims>(
        &data.token,
        &DecodingKey::from_secret(&state.secret_b_array),
        &Validation::default(),
    )
    .map_err(|_| GenericErr::Auth(AuthError::InvalidToken))?;

    if tkn_data.claims.tkn_type != TokenType::Refresh {
        return Err(GenericErr::Auth(AuthError::WrongTokenType));
    }

    let existence_key = format!("{BLACKLIST_STR}{}", tkn_data.claims.jti);
    let is_revoked: i64 = state
        .kvs_client
        .exists(existence_key)
        .await
        .map_err(|_| GenericErr::Internal(InternalError::RedisError))?;

    if is_revoked == 1 {
        return Err(GenericErr::Auth(AuthError::ExpiredToken));
    }

    state
        .pg_interface
        .select_one::<Uuid, User>((&["id"], &[tkn_data.claims.sub]))
        .await
        .map_err(|e| GenericErr::Internal(e))?;

    let now_utc = OffsetDateTime::now_utc();

    let refersh_uuid = Uuid::new_v4();

    let access = encode_to_jwt(AuthClaims {
            sub: tkn_data.claims.sub,
            jti: Uuid::new_v4(),
            rjti: Some(refersh_uuid),
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
            tkn_type: TokenType::Access,
        }, &state.secret_b_array)
            .await
            .map_err(|e| GenericErr::Internal(e))?;
        
        let refresh = encode_to_jwt(AuthClaims {
            sub: tkn_data.claims.sub,
            jti: Uuid::new_v4(),
            rjti: None,
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::days(3)).unix_timestamp() as u64,
            tkn_type: TokenType::Refresh,
        }, &state.secret_b_array)
            .await
            .map_err(|e| GenericErr::Internal(e))?;

    let set_key = format!("{BLACKLIST_STR}{}", tkn_data.claims.jti);
    let ttl = tkn_data.claims.exp as i64 - OffsetDateTime::now_utc().unix_timestamp() + 60;

    if ttl <= 0 {
        return Err(GenericErr::Auth(AuthError::InvalidToken));
    }

    state
        .kvs_client
        .set::<(), _, _>(
            set_key,
            1,
            Some(fred::types::Expiration::EX(ttl)),
            Some(fred::types::SetOptions::NX),
            false,
        )
        .await
        .map_err(|_| GenericErr::Internal(InternalError::RedisError))?;

    let res = TokenPair {
        access_tkn: access,
        refresh_tkn: refresh,
    };

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(res),
    });
}

pub async fn sign_up(
    auth: AuthInvite,
    mut state: State<AppState>,
    Json(data): Json<SignupCred>,
) -> Result<Res<UserTokenObj>, GenericErr> {
    let key = format!("{INVITES_BLACKLIST_STR}{}", auth.claims.jti);

    if data.nickname.trim().len() < 3 {
        return Err(GenericErr::Auth(AuthError::InvalidNickname));
    }

    if data.username.trim().len() < 3 || data.password.trim().len() < 3 {
        return Err(GenericErr::Internal(
            InternalError::InvalidAccountCredentials,
        ));
    }
    let mut tr = state.pg_interface.begin_transaction()
    .await.map_err(|e| GenericErr::Internal(e))?;

    //TODO: assign an actual ds to the user or let them choose idc
    let user: User = tr
        .insert_one(
            User {
                id: PLACE_HOLDER_UUID,
                prv: auth.claims.priv_level,
                home_ds: Uuid::new_v4(),
                nickname: data.nickname,
                username: data.username,
                password: data.password,
                pfp: None,
            },
            false,
        )
        .await
        .map_err(|e| GenericErr::Internal(e))?;

    let now_utc = OffsetDateTime::now_utc();

    let refersh_uuid = Uuid::new_v4();

    let access = encode_to_jwt(AuthClaims {
        sub: user.id,
        jti: Uuid::new_v4(),
        rjti: Some(refersh_uuid),
        iat: now_utc.clone().unix_timestamp() as u64,
        exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
        tkn_type: TokenType::Access,
    }, &state.secret_b_array)
        .await
        .map_err(|e| GenericErr::Internal(e))?;
    
    let refresh = encode_to_jwt(AuthClaims {
        sub: user.id,
        jti: Uuid::new_v4(),
        rjti: None,
        iat: now_utc.clone().unix_timestamp() as u64,
        exp: (now_utc.clone() + Duration::days(3)).unix_timestamp() as u64,
        tkn_type: TokenType::Refresh,
    }, &state.secret_b_array)
        .await
        .map_err(|e| GenericErr::Internal(e))?;

    tr.commit()
    .await.map_err(|e| GenericErr::Internal(e))?;

    let res = UserTokenObj {
        user_data: user,
        token_data: TokenPair {
            access_tkn: access,
            refresh_tkn: refresh,
        },
    };

    let ttl = auth.claims.exp as i64 - OffsetDateTime::now_utc().unix_timestamp() + 60;

    if ttl <= 0 {
        return Err(GenericErr::Auth(AuthError::InvalidToken));
    }

    state
        .kvs_client
        .set::<(), &String, i8>(
            &key,
            1,
            Some(fred::types::Expiration::EX(ttl)),
            Some(fred::types::SetOptions::NX),
            false,
        )
        .await
        .map_err(|_| GenericErr::Internal(InternalError::RedisError))?;

    Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(res),
    })
}

pub async fn mint_ds_token(auth: AuthUser, State(mut state): State<AppState>, Json(data): Json<DsCreds>) -> Result<Res<SingleJwtObj>, InternalError> {
    state.pg_interface.select_one::<Uuid, Device>((&["id"], &[data.device_id])).await?;

    let now = OffsetDateTime::now_utc();
    let claims = DsClaims {
        sub: auth.user_id,
        aud: data.ds_id,
        device_id: data.device_id,
        iat: now.clone().unix_timestamp() as u64,
        exp: (now + Duration::minutes(10)).unix_timestamp() as u64
    };

    let ds_token = encode_to_jwt(claims, &state.secret_b_array).await?;

    return Ok(Res { 
        status: StatusCode::OK, 
        success: true, 
        msg: String::new(), 
        data: Some(SingleJwtObj {
        token: ds_token
    })});
}

pub async fn create_new_user_invite(
    auth: AuthUser,
    State(mut state): State<AppState>,
    Json(data): Json<PrivLevel>,
) -> Result<Res<SingleJwtObj>, GenericErr> {
    let user: User = state
        .pg_interface
        .select_one((&["id"], &vec![auth.user_id]))
        .await
        .map_err(|e| GenericErr::Internal(e))?;

    if user.prv != PrivilegeT::Proprietor {
        return Err(GenericErr::Auth(AuthError::InvalidPrivilige));
    }

    let now_utc = OffsetDateTime::now_utc();
    let claims =  PrivClaims {
        priv_level: data.prv_level,
        jti: Uuid::new_v4(),
        iat: now_utc.clone().unix_timestamp() as u64,
        exp: (now_utc + Duration::minutes(30)).unix_timestamp() as u64,
    };

    let inv_jwt = encode_to_jwt(claims, &state.secret_b_array)
        .await
        .map_err(|e| GenericErr::Internal(e))?;

    return Ok(Res {
        status: StatusCode::CREATED,
        success: true,
        msg: String::new(),
        data: Some(SingleJwtObj { token: inv_jwt }),
    });
}

pub async  fn add_device(
    auth: AuthUser, 
    State(mut state): State<AppState>, 
    Json(data): Json<DeviceCreateInfo>) -> Result<Res<()>, GenericErr> {
    return Err(GenericErr::Internal(InternalError::BadRequest));
}
