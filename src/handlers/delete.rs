// use axum::extract::{Path, State};
// use axum::http::StatusCode;
// use uuid::Uuid;

// use crate::handlers::fetch_guild_member;
// use crate::responses::error_t::{AuthError, GenericErr, InternalError};
// use crate::{auth::extractor::AuthUser, types::*};

// pub async fn delete_self(
//     auth: AuthUser,
//     State(mut state): State<AppState>,
// ) -> Result<Res<()>, InternalError> {
//     let query = sqlx::query_as!(
//         Guild,
//         "SELECT guilds.* FROM guilds
//         JOIN guild_members gm ON gm.guild_id = guilds.id
//         WHERE gm.member_id = $1
//         AND gm.rank = $2
//         AND (SELECT COUNT(*) FROM guild_members gm2
//             WHERE gm2.guild_id = guilds.id AND gm2.rank = $2
//         ) = 1;",
//         auth.user_id,
//         RankT::Owner as RankT
//     );

//     let orphan_guilds = state.pg_interface.generic_fetch(query).await?;

//     if !orphan_guilds.is_empty() {
//         return Err(InternalError::DetachingOperation);
//     }

//     let deletes = state
//         .pg_interface
//         .delete_many::<Uuid, User>(&vec![auth.user_id])
//         .await?;

//     if !deletes.is_empty() {
//         return Ok(Res {
//             status: StatusCode::OK,
//             success: true,
//             msg: String::new(),
//             data: None,
//         });
//     } else {
//         return Err(InternalError::NoMatches);
//     }
// }