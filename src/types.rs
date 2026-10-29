#![allow(warnings)]
use std::sync::Arc;

use crate::{certificates::intermediate_keys::Pki, db::*};
use axum::http::StatusCode;
use base64::engine::{GeneralPurpose, general_purpose::URL_SAFE_NO_PAD};
use derive_macros::Bindable;
use ed25519_dalek::VerifyingKey;
use fred::clients::Client;
use serde::{Deserialize, Serialize};
use sqlx::{Database, Postgres, postgres::PgArguments, query::QueryAs};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

/* ===== CONSTS ===== */

pub const BLACKLIST_STR: &'static str = "jwt:blacklist:";
pub const INVITES_BLACKLIST_STR: &'static str = "jwt:blacklist:invites:";

pub const PLACE_HOLDER_UUID: Uuid = Uuid::nil();

pub const REG_LBL: &[u8] = b"herpesz-api";

pub const B64_ENGINE: GeneralPurpose= URL_SAFE_NO_PAD;

/* ===== TRAITS ===== */

pub trait Bindable<DB: Database> {
    fn table_name() -> &'static str;

    fn columns() -> &'static [&'static str];
    fn id_columns() -> &'static [&'static str];
    fn base_columns() -> &'static [&'static str];

    fn bind_values<'lftm>(
        &'lftm self,
        query: QueryAs<'lftm, DB, Self, DB::Arguments>,
        bind_val: BindVal,
    ) -> QueryAs<'lftm, DB, Self, DB::Arguments>
    where
        Self: Sized;
}

/* ===== ENUMS ===== */

#[derive(PartialEq)]
pub enum BindVal {
    ID,
    BASE,
    ALL,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "relation_t")]
pub enum RelationT {
    Friends,
    Pending,
    Blocked,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize, Clone, PartialEq)]
#[sqlx(type_name = "privilege_t")]
pub enum PrivilegeT {
    Consumer,
    Proprietor,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[sqlx(type_name = "rank_t")]
pub enum RankT {
    User,
    Admin,
    Owner,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "channel_t")]
pub enum ChannelT {
    Text,
    Voice,
}

/* ===== STRUCTS ===== */

pub struct Res<T>
where
    T: Serialize,
{
    pub status: StatusCode,
    pub success: bool,
    pub msg: String,
    pub data: Option<T>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct User {
    pub id: Uuid,
    pub prv: PrivilegeT,
    pub home_ds: Uuid,
    pub nickname: String,
    pub username: String,
    pub password: String,
    pub pfp: Option<String>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub cert_der: Vec<u8>,
    pub cert_serial: Vec<u8>,
    pub cert_not_after: i64,
    pub key_id: String,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "user_id"]
pub struct Deletion {
    pub user_id: Uuid,
}

#[derive(Clone)]
pub struct AppState {
    pub secret_b_array: Arc<[u8]>,
    pub pg_interface: DbInterface<DbPool<Postgres>>,
    pub kvs_client: Client,
    pub pki: Pki,
}

#[derive(Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: Uuid,
    pub jti: Uuid,
    pub rjti: Option<Uuid>,
    pub iat: u64,
    pub exp: u64,
    pub tkn_type: TokenType,
}

#[derive(Serialize, Deserialize)]
pub struct DsClaims {
    pub sub: Uuid,
    pub aud: Uuid,
    pub device_id: Uuid,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PrivClaims {
    pub priv_level: PrivilegeT,
    pub jti: Uuid,
    pub iat: u64,
    pub exp: u64,
}

pub struct Intermediate {
    pub key_id: String,
    pub ski: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub subject: x509_cert::name::Name,
    pub signer: ed25519_dalek::SigningKey,
    pub not_before: i64,
    pub not_after: i64,
    pub active: bool,
}

pub struct IssuedLeaf {
    pub leaf_der: Vec<u8>,
    pub serial: Vec<u8>,
    pub not_after: i64,
    pub key_id: String,
    pub intermediate_der: Vec<u8>,
}


