mod db;
mod types;
mod handlers;
mod responses;
mod axum_trait_impls;

use std::{env, time::Duration};

use axum::{
    Router, http::{Method, StatusCode, header}, routing::{delete, get, patch, post},
};

use fred::{interfaces::ClientLike, types::{Builder, config::{Config, TcpConfig}}};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};
use uuid::Uuid;

use crate::{db::DbInterface, handlers::post::*, responses::error_t::InternalError, types::{PLACE_HOLDER_UUID, Res}};
use crate::types::PrivilegeT;
use types::{AppState, User};

async fn ensure_master_user(mut state: AppState) {
    let (usr_nm, pswrd) = (
        env::var("M_USERNAME").expect("the variable for the master user's username is expected"),
        env::var("M_PASSWORD").expect("the variable for the master user's password is expected"),
    );

    let user = state
        .pg_interface
        .select_one::<String, User>((
            &["username", "password"],
            &vec![usr_nm.clone(), pswrd.clone()],
        ))
        .await;

    let master_user =  User {
                        id: PLACE_HOLDER_UUID,
                        nickname: "master".to_string(),
                        prv: PrivilegeT::Proprietor,
                        username: usr_nm,
                        password: pswrd,
                        pfp: None,
                    };

    match user {
        Ok(u) if u.prv != PrivilegeT::Proprietor => {
            state.pg_interface.delete_many::<Uuid, User>(&[u.id]).await.expect("generic db ops are expected to succeed");
            state.pg_interface.insert_one(master_user, false).await.expect("generic db ops are expected to succeed");
        }
        Err(e) if e == InternalError::NoMatches => {
            state.pg_interface.insert_one(master_user, false)
            .await.expect("generic db ops are expected to succeed");
        }
        Err(_) => {
            panic!("generic db ops are expected to succeed")
        }
        _ => {}
    }
}

async fn setup() -> AppState {
    let db_opt = PgConnectOptions::new()
        .socket("/run/postgresql")
        .username(
            &std::env::var("PS_USERNAME").expect("a PS_USERNAME enviroment variable is expected"),
        )
        .database("records_ps");

    let db_conn_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect_with(db_opt)
        .await.expect("connection pool initialization is expected to succeed");

    let conf = Config::from_url("redis://localhost:6379/1").expect("redis binding is expected to succeed");

    let kv_client = Builder::from_config(conf)
    .with_connection_config(|config| {
        config.connection_timeout = Duration::from_secs(1);
        config.tcp = TcpConfig {
            nodelay: Some(true),
            ..Default::default()
        }
    })
    .build().expect("kv client construction is expected to succeed");

    kv_client
        .init()
        .await
        .expect("client init is expected to succeed");

    let state = AppState {
        secret_b_array: env::var("SECRET")
            .expect("the jwt secret is expected to exist")
            .into_bytes()
            .into(),
        pg_interface: DbInterface::new(db_conn_pool)
            .await
            .expect("failed to create the postgres db connection"),
        kvs_client: kv_client,
    };

    ensure_master_user(state.clone()).await;

    return state;
}

async fn palceholder_handler() -> Res<()> {
    Res{
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect("a .env file is expected");
    let state = setup().await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600));

    let auth: Router<AppState> = Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/sign_up", post(sign_up))
        .route("/invite_new_user", post(create_new_user_invite))
        .route("/ds-token", post(mint_ds_token));

    let devices: Router<AppState> = Router::new()
        .route("/register", post(palceholder_handler))
        .route("/all", get(palceholder_handler))
        .route("/{device_id}", delete(palceholder_handler));

    let users: Router<AppState> = Router::new()
        .route("/me", delete(palceholder_handler))
        .route("/me", patch(palceholder_handler))
        .route("/{user_id}/profile", get(palceholder_handler))
        .route("/{user_id}/devices", get(palceholder_handler))
        .route("/lookup", get(palceholder_handler));

    let pki: Router<AppState> = Router::new()
        .route("/intermediates", get(palceholder_handler))
        .route("/well-known", get(palceholder_handler));

    let dir: Router<AppState> = Router::new()
        .route("/intermediates", get(palceholder_handler))
        .route("/well-known", get(palceholder_handler));

    let api = Router::new()
        /* ===== INVITES ===== */
        .route("/invite_new_user", post(palceholder_handler))
        /* ===== AUTH ===== */
        .nest("/auth", auth)
        /* ===== USERS ===== */
        .nest("/user", users)
        /* ===== PKI ===== */
        .nest("/pki", pki)
        /* ===== DIR ===== */
        .nest("/dir", dir)
        /* ===== DEVICES ===== */
        .nest("/device", devices)
        /* ===== STATE ===== */
        .layer(cors)
        .with_state(state);

    let interface: Router<()> = Router::new()
        .nest("/apiV1", api);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("port 8080 is required to be free");

    axum::serve(listener, interface)
        .await
        .expect("axum serve needs to start succesfully");
}
