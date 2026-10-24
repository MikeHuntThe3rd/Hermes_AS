use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use crate::{responses::error_t::InternalError};


pub async fn encode_to_jwt<C: Serialize>(
    claims: C,
    secret: &[u8]
) -> Result<String, InternalError> {
    return Ok(
        encode(
            &Header::default(), 
            &claims, 
            &EncodingKey::from_secret(secret)
        ).map_err(|_| InternalError::DecodeEncodeErr)?);
}
