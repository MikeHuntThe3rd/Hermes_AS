mod axum_trait_impls;
mod certificates;
mod db;
mod handlers;
mod responses;
mod types;

use std::{collections::HashMap, env, fs, sync::Arc, time::Duration, vec};

use axum::{
    Router,
    http::{Method, header},
    routing::{delete, get, patch, post},
};

use base64::Engine;
use der::{Decode, zeroize::Zeroize};
use ed25519_dalek::{SigningKey, VerifyingKey};
use fred::{
    interfaces::ClientLike,
    types::{
        Builder,
        config::{Config, TcpConfig},
    },
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;
use x509_cert::{
    certificate::{CertificateInner, Rfc5280},
    ext::pkix::SubjectKeyIdentifier,
};

use crate::{
    certificates::intermediate_keys::Pki,
    db::DbInterface,
    handlers::{
        delete::{delete_self, revoke_device},
        get::{
            get_deletions_from, get_devices, get_initial_deletions, get_intermediate_keys,
            get_jwt_okp_keys, get_signed_devices, get_user_profile, get_users_by_username,
        },
        patch::update_self,
        post::*,
    },
    responses::error_t::InternalError,
    types::{
        B64_ENGINE, BindVal, ED25519_PKCS8_PREFIX, Intermediate, JwtSignerKey, LogicalOp,
        PLACE_HOLDER_UUID,
    },
};
use crate::{handlers::get::get_signed_ds_eps, types::PrivilegeT};
use types::{AppState, User};

fn keys_from_seed(seed: &[u8; 32]) -> (EncodingKey, VerifyingKey) {
    let mut der = [0u8; 48];
    der[..16].copy_from_slice(&ED25519_PKCS8_PREFIX);
    der[16..].copy_from_slice(seed);

    let encoding = EncodingKey::from_ed_der(&der);

    der.zeroize();

    return (encoding, SigningKey::from_bytes(seed).verifying_key());
}

async fn ensure_master_user(mut state: AppState) {
    let username =
        env::var("M_USERNAME").expect("the variable for the master user's username is expected");
    let password =
        env::var("M_PASSWORD").expect("the variable for the master user's password is expected");

    let user = state
        .pg_interface
        .select_one::<String, User>(
            (
                &["username", "password"],
                &vec![username.clone(), password.clone()],
            ),
            LogicalOp::AND,
        )
        .await;

    let master_user = User {
        id: PLACE_HOLDER_UUID,
        prv: PrivilegeT::Proprietor,
        home_ds: Uuid::new_v4(),
        nickname: "master".to_string(),
        username: username,
        password: password,
        changes: 0,
        pfp: None,
    };

    match user {
        Ok(u) if u.prv != PrivilegeT::Proprietor => {
            let mut tr = state
                .pg_interface
                .begin_transaction()
                .await
                .expect("transction must be set up");

            tr.delete_matches::<Uuid, User>(&["id"], &vec![u.id], LogicalOp::AND)
                .await
                .expect("generic db ops are expected to succeed");
            tr.insert_one(master_user, BindVal::ND)
                .await
                .expect("generic db ops are expected to succeed");

            tr.commit().await.expect("transction must succeed");
        }
        Err(e) if e == InternalError::NoMatches => {
            state
                .pg_interface
                .insert_one(master_user, BindVal::ND)
                .await
                .expect("generic db ops are expected to succeed");
        }
        Err(_) => {
            panic!("generic db ops are expected to succeed")
        }
        _ => {}
    }
}

fn load_imks() -> Vec<Intermediate> {
    let imks_dir_path =
        env::var("IMKS_DIR_PATH").expect("a directory for the intermediate keys must be set");
    let imks_priv_key_paths =
        env::var("IMKS_PRIV_KEY_PATHS").expect("a directory for the intermediate keys must be set");
    let priv_key_paths: Vec<&str> = (&imks_priv_key_paths).split(';').collect();
    let mut pub_to_priv_keys: HashMap<[u8; 32], SigningKey> = HashMap::new();

    for priv_key_path in priv_key_paths {
        let priv_key_bytes = fs::read(priv_key_path).expect("file reads need to succeed");
        let secret_key_bytes: [u8; 32] = priv_key_bytes
            .as_slice()
            .try_into()
            .expect("the read private key is of invalid length");

        let signer = SigningKey::from_bytes(&secret_key_bytes);
        pub_to_priv_keys.insert(signer.verifying_key().to_bytes(), signer);
    }

    let dir = fs::read_dir(imks_dir_path).expect("given directory must exist");
    let mut files: Vec<Vec<u8>> = Vec::new();

    for file in dir {
        match file {
            Ok(k) => {
                let file_bytes = fs::read(k.path())
                    .expect("file reading is expected to succeed check permissions");

                files.push(file_bytes);
            }
            Err(_) => {
                panic!("a file entry couldnt be read")
            }
        }
    }

    let mut imks: Vec<Intermediate> = Vec::new();

    for der in files {
        let cert: CertificateInner<Rfc5280> =
            CertificateInner::from_der(&der).expect("der certificate bytes are invalid");
        let tbs = cert.tbs_certificate();

        let spki = cert.tbs_certificate().subject_public_key_info();
        let ski: Vec<u8> = tbs
            .get_extension::<SubjectKeyIdentifier>()
            .expect("extension extraction failed")
            .expect("no ski extension found")
            .1
            .0
            .as_bytes()
            .to_vec();

        let cert_pubk: &[u8; 32] = spki
            .subject_public_key
            .raw_bytes()
            .try_into()
            .expect("the public key in the certificate is invalid");

        let signer = pub_to_priv_keys
            .get(cert_pubk)
            .expect("there was no match for a public key");

        let not_before = tbs.validity().not_before.to_unix_duration().as_secs() as i64;
        let not_after = tbs.validity().not_after.to_unix_duration().as_secs() as i64;

        let imk = Intermediate {
            key_id: hex::encode(&ski),
            ski,
            cert_der: der,
            subject: tbs.subject().clone(),
            signer: signer.clone(),
            not_before,
            not_after,
            active: true,
        };
        imks.push(imk);
    }
    return imks;
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
        .await
        .expect("connection pool initialization is expected to succeed");

    let conf =
        Config::from_url("redis://localhost:6379/1").expect("redis binding is expected to succeed");

    let kv_client = Builder::from_config(conf)
        .with_connection_config(|config| {
            config.connection_timeout = Duration::from_secs(1);
            config.tcp = TcpConfig {
                nodelay: Some(true),
                ..Default::default()
            }
        })
        .build()
        .expect("kv client construction is expected to succeed");

    kv_client
        .init()
        .await
        .expect("client init is expected to succeed");

    let secret_bytes: [u8; 32] = env::var("SECRET")
        .expect("the jwt secret is expected to exist")
        .into_bytes()
        .try_into()
        .expect("the string needs to be serializable to a size 32 byte array");

    let (jwt_encoding, public_key) = keys_from_seed(&secret_bytes);
    let pulic_key_b64 = B64_ENGINE.encode(public_key.as_bytes());
    let state = AppState {
        jwt_okp: Arc::new(JwtSignerKey {
            kid: Uuid::new_v4(),
            kty: "OKP".to_string(),
            alg: "EdDSA".to_string(),
            crv: "Ed25519".to_string(),
            usage: "sig".to_string(),
            encoding: jwt_encoding,
            decoding: DecodingKey::from_ed_components(&pulic_key_b64)
                .expect("DecodingKey generation is expected to succeed"),
            x: pulic_key_b64,
        }),
        pg_interface: DbInterface::new(db_conn_pool)
            .await
            .expect("failed to create the postgres db connection"),
        kvs_client: kv_client,
        pki: Pki {
            intermediates: Arc::new(load_imks()),
        },
    };

    ensure_master_user(state.clone()).await;

    return state;
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
        .route("/register", post(add_device))
        .route("/all", get(get_devices))
        .route("/{device_id}", delete(revoke_device));

    let users: Router<AppState> = Router::new()
        .route("/me", delete(delete_self))
        .route("/me", patch(update_self))
        .route("/{user_id}/profile", get(get_user_profile))
        .route("/{user_id}/devices", get(get_signed_devices))
        .route("/lookup/{nickname}", get(get_users_by_username));

    let pki: Router<AppState> = Router::new()
        .route("/intermediates", get(get_intermediate_keys))
        .route("/JWKS", get(get_jwt_okp_keys));

    let dir: Router<AppState> = Router::new()
        .route("/ds-providers", get(get_signed_ds_eps))
        .route("/deletions/initial", get(get_initial_deletions))
        .route("/deletions/{cursor}", get(get_deletions_from));

    let api = Router::new()
        /* ===== INVITES ===== */
        .route("/invite_new_user", post(create_new_user_invite))
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

    let interface: Router<()> = Router::new().nest("/apiV1", api);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("port 8080 is required to be free");

    axum::serve(listener, interface)
        .await
        .expect("axum serve needs to start succesfully");
}
