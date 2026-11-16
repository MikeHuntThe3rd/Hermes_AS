#![allow(warnings)]
use std::{ops::DerefMut, sync::Arc};

use crate::{certificates::intermediate_keys::Pki, db::*, responses::error_t::InternalError};
use axum::http::StatusCode;
use base64::engine::{GeneralPurpose, general_purpose::URL_SAFE_NO_PAD};
use derive_macros::Bindable;
use ed25519_dalek::{SigningKey, VerifyingKey};
use fred::clients::Client;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use sqlx::{Database, Postgres, postgres::PgArguments, query::QueryAs};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use x509_cert::serial_number;

/* ===== CONSTS ===== */

pub const BLACKLIST_STR: &'static str = "jwt:blacklist:";
pub const INVITES_BLACKLIST_STR: &'static str = "jwt:blacklist:invites:";

pub const PLACE_HOLDER_UUID: Uuid = Uuid::nil();

pub const REG_LBL: &[u8] = b"herpesz-api";

pub const B64_ENGINE: GeneralPurpose = URL_SAFE_NO_PAD;

pub const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/* ===== TRAITS ===== */

pub trait Bindable<DB: Database> {
    fn table_name() -> &'static str;

    fn columns() -> &'static [&'static str];
    fn id_columns() -> &'static [&'static str];
    fn base_columns() -> &'static [&'static str];
    fn non_default_columns() -> &'static [&'static str];

    fn bind_values<'lftm>(
        &'lftm self,
        query_builder: &mut sqlx::query_builder::Separated<'lftm, DB, &'static str>,
        bind_val: &BindVal,
    ) where
        Self: Sized;
}

pub trait Connect {
    type DB: Database;
    type Conn<'a>: DerefMut<Target = <Self::DB as Database>::Connection> + Send
    where
        Self: 'a;

    async fn conn(&mut self) -> Result<Self::Conn<'_>, InternalError>;
}

/* ===== ENUMS ===== */

#[derive(PartialEq)]
pub enum BindVal {
    ID,
    BASE,
    ALL,
    ND,
}

#[derive(PartialEq)]
pub enum LogicalOp {
    AND,
    OR,
    IN,
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
    #[has_default]
    pub id: Uuid,
    pub prv: PrivilegeT,
    pub home_ds: Uuid,
    pub nickname: String,
    pub username: String,
    pub password: String,
    pub changes: i64,
    #[has_default]
    pub pfp: Option<String>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub cert_der: Vec<u8>,
    pub sig_pubkey: Vec<u8>,
    pub cert_serial: Vec<u8>,
    pub cert_not_after: i64,
    pub key_id: String,
    pub is_revoked: bool,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "seq"]
pub struct Deletion {
    #[has_default]
    pub seq: i64,
    pub user_id: Uuid,
    pub deleted_at: i64,
    pub key_id: String,
    pub signature: Vec<u8>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct Ds {
    pub id: Uuid,
    pub ep: String,
}

pub struct JwtSignerKey {
    pub kid: Uuid,
    pub kty: String,
    pub usage: String,
    pub crv: String,
    pub alg: String,
    pub x: String,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

#[derive(Clone)]
pub struct AppState {
    pub jwt_okp: Arc<JwtSignerKey>,
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
