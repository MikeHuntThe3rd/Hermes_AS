use crate::{responses::error_t::InternalError, types::AppState};
use jsonwebtoken::{Header, encode};
use serde::Serialize;

pub fn encode_to_jwt<C>(claims: C, state: &AppState) -> Result<String, InternalError>
where
    C: Serialize,
{
    let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(state.jwt_okp.kid.to_string());
    return Ok(encode(&header, &claims, &state.jwt_okp.encoding)
        .map_err(|_| InternalError::DecodeEncodeErr)?);
}
