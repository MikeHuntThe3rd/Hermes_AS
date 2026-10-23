#![allow(warnings)]
use std::sync::Arc;

use crate::db::*;
use axum::http::StatusCode;
use derive_macros::Bindable;
use fred::clients::Client;
use serde::{Deserialize, Serialize};
use sqlx::{Database, Postgres, postgres::PgArguments, query::QueryAs};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

/* ===== CONSTS ===== */

pub const BLACKLIST_STR: &'static str = "jwt:blacklist:";
pub const INVITES_BLACKLIST_STR: &'static str = "jwt:blacklist:invites:";

pub const PLACE_HOLDER_UUID: Uuid = Uuid::nil();

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
    pub nickname: String,
    pub prv: PrivilegeT,
    pub username: String,
    pub password: String,
    pub pfp: Option<Uuid>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Guild {
    pub id: Uuid,
    pub name: String,
    pub gp: Option<Uuid>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Channel {
    pub id: Uuid,
    pub guild_id: Uuid,
    pub name: String,
    pub category: ChannelT,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Dm {
    pub id: Uuid,
    pub user_a: Option<Uuid>,
    pub user_b: Option<Uuid>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Guild_Invite {
    pub id: Uuid,
    pub guild_id: Uuid,
    pub recipient: Uuid,
    pub rank: RankT,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Dm_Invite {
    pub id: Uuid,
    pub dm_id: Uuid,
    pub recipient: Uuid,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "guild_id;member_id"]
#[include_ids(true)]
pub struct Guild_Member {
    pub guild_id: Uuid,
    pub member_id: Uuid,
    pub rank: RankT,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Dm_Message {
    pub id: i64,
    pub dm_id: Uuid,
    pub message: Option<String>,
    pub user_id: Option<Uuid>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Guild_Message {
    pub id: i64,
    pub channel_id: Uuid,
    pub message: Option<String>,
    pub user_id: Option<Uuid>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "id"]
pub struct Object {
    pub id: Uuid,
    pub hash: String,
    pub rel_path: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub creation_timestamp: i64,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "message_id;object_id"]
#[include_ids(true)]
pub struct Dm_Message_Object {
    pub message_id: i64,
    pub object_id: Uuid,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "message_id;object_id"]
#[include_ids(true)]
pub struct Guild_Message_Object {
    pub message_id: i64,
    pub object_id: Uuid,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable)]
#[ids = "relating_user;related_user"]
pub struct Relation {
    pub relating_user: Uuid,
    pub related_user: Uuid,
    pub state: RelationT,
}

type CallId = Uuid;
type RoomId = Uuid;
type UserId = Uuid;

#[derive(Clone)]
pub struct AppState {
    pub secret_b_array: Arc<[u8]>,
    pub pg_interface: DbInterface<DbPool<Postgres>>,
    pub kvs_client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub jti: Uuid,
    pub iat: usize,
    pub exp: usize,
    pub tkn_type: TokenType,
}

#[derive(Serialize, Deserialize)]
pub struct PrivClaims {
    pub priv_level: PrivilegeT,
    pub jti: Uuid,
    pub iat: usize,
    pub exp: usize,
}
