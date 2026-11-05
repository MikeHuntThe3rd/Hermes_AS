use crate::{
    responses::error_t::InternalError,
    types::{AppState, B64_ENGINE, FetchableSignature},
};
use base64::Engine;
use ed25519_dalek::Signer;
use jsonwebtoken::{Header, encode};
use serde::Serialize;

pub fn encode_to_jwt<C>(claims: C, state: &AppState) -> Result<String, InternalError>
where
    C: Serialize + FetchableSignature,
{
    let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(state.jwt_okp.kid.to_string());
    return Ok(encode(&header, &claims, &state.jwt_okp.encoding)
        .map_err(|_| InternalError::DecodeEncodeErr)?);
}
