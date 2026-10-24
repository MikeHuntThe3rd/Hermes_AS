use axum::{Json, extract::State, http::StatusCode};
use fred::interfaces::KeysInterface;
use jsonwebtoken::{DecodingKey, Validation, decode};
use crate::{axum_trait_impls::extractors::AuthInvite, responses::error_t::*};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{axum_trait_impls::creation::encode_to_jwt, responses::error_t::GenericErr, types::*};

#[derive(Serialize, Deserialize)]
pub struct UserTokenObj {
    pub user_data: User,
    pub token_data: TokenPair,
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

#[derive(Deserialize)]
pub struct LoginCred {
    pub username: String,
    pub password: String,
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

        let access = encode_to_jwt(AuthClaims {
            sub: user.id,
            jti: Uuid::new_v4(),
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
            tkn_type: TokenType::Access,
        }, &state.secret_b_array)
            .await
            .map_err(|e| GenericErr::Internal(e))?;
        
        let refresh = encode_to_jwt(AuthClaims {
            sub: user.id,
            jti: Uuid::new_v4(),
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
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

    let access = encode_to_jwt(AuthClaims {
            sub: tkn_data.claims.sub,
            jti: Uuid::new_v4(),
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
            tkn_type: TokenType::Access,
        }, &state.secret_b_array)
            .await
            .map_err(|e| GenericErr::Internal(e))?;
        
        let refresh = encode_to_jwt(AuthClaims {
            sub: tkn_data.claims.sub,
            jti: Uuid::new_v4(),
            iat: now_utc.clone().unix_timestamp() as u64,
            exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
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

    let user: User = tr
        .insert_one(
            User {
                id: PLACE_HOLDER_UUID,
                nickname: data.nickname,
                prv: auth.claims.priv_level,
                username: data.username,
                password: data.password,
                pfp: None,
            },
            false,
        )
        .await
        .map_err(|e| GenericErr::Internal(e))?;

    let now_utc = OffsetDateTime::now_utc();

    let access = encode_to_jwt(AuthClaims {
        sub: user.id,
        jti: Uuid::new_v4(),
        iat: now_utc.clone().unix_timestamp() as u64,
        exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
        tkn_type: TokenType::Access,
    }, &state.secret_b_array)
        .await
        .map_err(|e| GenericErr::Internal(e))?;
    
    let refresh = encode_to_jwt(AuthClaims {
        sub: user.id,
        jti: Uuid::new_v4(),
        iat: now_utc.clone().unix_timestamp() as u64,
        exp: (now_utc.clone() + Duration::minutes(10)).unix_timestamp() as u64,
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

pub async fn mint_ds_token(State(state): State<AppState>) -> Result<Res<SingleJwtObj>, GenericErr> {
    return Err(GenericErr::Auth(AuthError::Blocked));
}
