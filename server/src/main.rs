use std::{collections::HashMap, sync::{RwLock, Arc}};

use common::{NewAuthentication, NewRegistration};
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, Json};
use url::Url;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use tower::ServiceBuilder;
use webauthn_rs::{
    prelude::{
        Passkey,
        CredentialID, RegisterPublicKeyCredential, PublicKeyCredential
    },
    Webauthn
};
use tower_sessions::{
    SessionManagerLayer,
    MemoryStore,
    Session
};

enum ServerError {
    Unknown,
    UserNotFound,
    UsernameExists,
    SessionError,
    NoRegistrationState,
    NoAuthenticationState,
    NoCredentials,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let body = match self {
            Self::Unknown => "unknown",
            Self::UserNotFound => "user not found",
            Self::UsernameExists => "username exists",
            Self::SessionError => "session error",
            Self::NoRegistrationState => "no registration state",
            Self::NoAuthenticationState => "no authentication state",
            Self::NoCredentials => "no credentials",
        };

        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

#[derive(Serialize, Deserialize)]
struct User {
    id: Uuid,
    username: Box<str>,
    keys: RwLock<HashMap<Box<str>, Passkey>>
}

#[derive(Serialize, Deserialize)]
struct Db {
    #[serde(skip)]
    username_index: RwLock<HashMap<Box<str>, Uuid>>,
    users: RwLock<HashMap<Uuid, User>>,
}

impl Db {
    fn add_user(&self, username: Box<str>) -> Result<Option<Uuid>, &'static str> {
        let mut uuid = uuid::Uuid::new_v4();
        let mut usernames_writer = self.username_index.write()
            .map_err(|_err| "failed to write username_index rwlock")?;
        let mut users_writer = self.users.write()
            .map_err(|_err| "failed to write users rwlock")?;

        if usernames_writer.contains_key(&username) {
            return Ok(None);
        }

        loop {
            if users_writer.contains_key(&uuid) {
                uuid = uuid::Uuid::new_v4();
            } else {
                break;
            }
        }

        usernames_writer.insert(username.clone(), uuid);
        users_writer.insert(uuid, User {
            id: uuid,
            username,
            keys: RwLock::new(HashMap::new())
        });
        
        Ok(Some(uuid))
    }

    fn save(&self) -> Result<(), &'static str> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open("./db.json")
            .map_err(|_err| "failed to create db.json")?;
        let writer = std::io::BufWriter::new(file);

        serde_json::to_writer_pretty(writer, self)
            .map_err(|_err| "failed writing to db.json")?;

        Ok(())
    }

    fn load() -> Result<Self, &'static str> {
        match std::fs::OpenOptions::new().read(true).open("./db.json") {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);

                let db: Db = serde_json::from_reader(reader)
                    .map_err(|_err|"failed to read db.json")?;

                {
                    let reader = db.users.read().map_err(|_err| "failed to read users rwlock")?;
                    let mut writer = db.username_index.write().map_err(|_err| "failed to write usernames rwlock")?;

                    for (id, user) in reader.iter() {
                        writer.insert(user.username.clone(), id.clone());
                    }
                }

                Ok(db)
            },
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => {
                    let default = Db {
                        username_index: RwLock::new(HashMap::new()),
                        users: RwLock::new(HashMap::new()),
                    };

                    default.save()?;

                    Ok(default)
                },
                _ => {
                    Err("error when reading db.json")
                }
            }
        }
    }
}

struct Sec {
    webauthn: Webauthn
}

impl Sec {
    fn default() -> Result<Self, &'static str> {
        let rp_id = "dac098.com";
        let rp_origin = Url::parse("https://dac098.com").unwrap();

        let webauthn = webauthn_rs::WebauthnBuilder::new(rp_id, &rp_origin)
            .map_err(|_err| "failed to create WebauthnBuilder")?
            .allow_any_port(true)
            .allow_subdomains(true)
            .build()
            .map_err(|_err| "failed to create Webauthn")?;

        Ok(Sec { webauthn })
    }
}

struct AppState {
    db: Db,
    sec: Sec
}

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");

    env_logger::init();

    let state = Arc::new(AppState {
        db: Db::load().expect("failed loading db.json"),
        sec: Sec::default().expect("failed creating sec"),
    });

    let session_store = MemoryStore::default();
    let layer_builder = ServiceBuilder::new()
        .layer(axum::error_handling::HandleErrorLayer::new(|err: axum::BoxError| async move {
            log::error!("axum HandleErrorLayer {:?}", err);

            StatusCode::INTERNAL_SERVER_ERROR
        }))
        .layer(SessionManagerLayer::new(session_store));

    let app = Router::new()
        .route("/ping", axum::routing::get(ping))
        .route("/registration/start", axum::routing::post(registration_start))
        .route("/registration/finish", axum::routing::post(registration_finish))
        .route("/authentication/start", axum::routing::post(authentication_start))
        .route("/authentication/finish", axum::routing::post(authentication_finish))
        .with_state(state)
        .layer(layer_builder);

    log::info!("starting webauthn server on ::1:8000");

    let listener = tokio::net::TcpListener::bind("::1:8000")
        .await
        .expect("failed to bind to ::1:8000");

    let server = axum::serve(listener, app);

    if let Err(err) = server.await {
        log::error!("server error {:?}", err);
    }
}

async fn ping() -> StatusCode {
    log::info!("ping request");

    StatusCode::OK
}

async fn registration_start(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(new_reg): Json<NewRegistration>
) -> Result<impl IntoResponse, ServerError> {
    log::info!("registration_start request");

    let (id, keys) = {
        let maybe_id = {
            let Ok(username_reader) = state.db.username_index.read() else {
                log::error!("registration_start failed opening usernames rwlock");

                return Err(ServerError::Unknown);
            };

            username_reader.get(&new_reg.username).cloned()
        };

        if let Some(uuid) = maybe_id {
            let Ok(users_reader) = state.db.users.read() else {
                log::error!("registration_start failed opening users rwlock");

                return Err(ServerError::Unknown);
            };

            let Ok(keys_reader) = users_reader.get(&uuid).unwrap().keys.read() else {
                log::error!("registration_start failed opening user keys rwlock");

                return Err(ServerError::Unknown);
            };

            let known_keys: Vec<CredentialID> = keys_reader.iter()
                .map(|(_name, key)| key.cred_id().clone())
                .collect::<Vec<CredentialID>>();

            if known_keys.len() > 0 {
                (uuid, Some(known_keys))
            } else {
                (uuid, None)
            }
        } else {
            match state.db.add_user(new_reg.username.clone()) {
                Ok(Some(uuid)) => {
                    if let Err(err) = state.db.save() {
                        log::warn!("registration_finish failed to save db {:?}", err);
                    }

                    (uuid, None)
                },
                Ok(None) => {
                    return Err(ServerError::UsernameExists);
                },
                Err(err) => {
                    log::error!("registration_start failed adding user {:?}", err);

                    return Err(ServerError::Unknown);
                }
            }
        }
    };

    if let Err(err) = session.remove_value("reg_state").await {
        log::error!("registration_start failed to remove reg_state from session {:?}", err);

        return Err(ServerError::SessionError);
    };

    let response = match state.sec.webauthn.start_passkey_registration(
        id,
        &new_reg.username,
        &new_reg.username,
        keys
    ) {
        Ok((ccr, reg_state)) => {
            if let Err(err) = session.insert("reg_state", (id, new_reg.key_name, reg_state)).await {
                log::error!("registration_start failed to insert registration into session state {:?}", err);

                return Err(ServerError::Unknown);
            }

            Json(ccr)
        },
        Err(err) => {
            log::error!("registration_start failed start_passkey_registration {:?}", err);

            return Err(ServerError::Unknown);
        }
    };

    Ok(response)
}

async fn registration_finish(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(reg): Json<RegisterPublicKeyCredential>
) -> Result<impl IntoResponse, ServerError> {
    log::info!("registration_finish request");

    let Ok(maybe_reg_state) = session.get("reg_state").await else {
        log::error!("registration_finish failed getting reg_state session data");

        return Err(ServerError::SessionError);
    };

    let Some((id, key_name, reg_state)) = maybe_reg_state else {
        return Err(ServerError::NoRegistrationState);
    };

    if let Err(err) = session.remove_value("reg_state").await {
        log::error!("registration_finish failed to remove reg_state from session {:?}", err);

        return Err(ServerError::SessionError);
    };

    log::debug!("reg {:#?}\nreg_state: {:#?}", reg, reg_state);

    let res = match state.sec.webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(sk) => {
            {
                let Ok(user_reader) = state.db.users.read() else {
                    log::error!("registration_finish failed opening users rwlock");

                    return Err(ServerError::Unknown);
                };

                let Some(user) = user_reader.get(&id) else {
                    log::error!("registration_finish user not found");

                    return Err(ServerError::UserNotFound);
                };

                let Ok(mut keys_writer) = user.keys.write() else {
                    log::error!("registration_finish failed opening write for user keys rwlock");

                    return Err(ServerError::Unknown);
                };

                keys_writer.insert(key_name, sk);
            }

            if let Err(err) = state.db.save() {
                log::warn!("registration_finish failed saving db {:?}", err);
            }

            StatusCode::OK
        },
        Err(err) => {
            log::warn!("registration_finish failed passkey registration {:?}", err);

            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}

async fn authentication_start(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(given): Json<NewAuthentication>
) -> Result<impl IntoResponse, ServerError> {
    log::info!("authentication_start request");

    if let Err(err) = session.remove_value("auth_state").await {
        log::error!("authentication_start failed to remove auth_state from session {:?}", err);

        return Err(ServerError::SessionError);
    };

    let (id, creds) = {
        let uuid = {
            let Ok(username_reader) = state.db.username_index.read() else {
                log::error!("authentication_start failed opening usernames rwlock");

                return Err(ServerError::Unknown);
            };

            let Some(uuid) = username_reader.get(&given.username) else {
                return Err(ServerError::UserNotFound);
            };

            uuid.clone()
        };

        let Ok(user_reader) = state.db.users.read() else {
            log::error!("authentication_start failed opening users rwlock");

            return Err(ServerError::Unknown);
        };

        let Ok(keys_reader) = user_reader.get(&uuid).unwrap().keys.read() else {
            log::error!("authentication_start failed opening user keys rwlock");

            return Err(ServerError::Unknown);
        };

        let known_keys: Vec<Passkey> = keys_reader.iter()
            .map(|(_name, key)| key.clone())
            .collect();

        (uuid, known_keys)
    };

    if creds.len() == 0 {
        return Err(ServerError::NoCredentials);
    }

    let res = match state.sec.webauthn.start_passkey_authentication(&creds) {
        Ok((rcr, auth_state)) => {
            if let Err(err) = session.insert("auth_state", (id, auth_state)).await {
                log::error!("authentication_start failed to insert authentication state into session {:?}", err);

                return Err(ServerError::SessionError);
            }

            Json(rcr)
        },
        Err(err) => {
            log::error!("authentication_start failed start passkey authentication {:?}", err);

            return Err(ServerError::Unknown);
        }
    };

    Ok(res)
}

async fn authentication_finish(
    State(state): State<Arc<AppState>>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, ServerError> {
    log::info!("authentication_finish request");

    let Ok(maybe_auth_state) = session.get("auth_state").await else {
        log::error!("authentication_finish failed to get auth_state session data");

        return Err(ServerError::SessionError);
    };

    let Some((id, auth_state)) = maybe_auth_state else {
        return Err(ServerError::NoAuthenticationState);
    };

    if let Err(err) = session.remove_value("auth_state").await {
        log::error!("authentication_finish failed to remove auth_state from session {:?}", err);

        return Err(ServerError::SessionError);
    };

    let res = match state.sec.webauthn.finish_passkey_authentication(&auth, &auth_state) {
        Ok(auth_result) => {
            let mut did_update = false;

            {
                let Ok(user_reader) = state.db.users.read() else {
                    log::error!("authentication_finish failed opening users rwlock");

                    return Err(ServerError::Unknown);
                };

                let Some(user) = user_reader.get(&id) else {
                    log::error!("authentication_finish user was not found");

                    return Err(ServerError::Unknown);
                };

                let Ok(mut keys_writer) = user.keys.write() else {
                    log::error!("authentication_finish failed opening user keys rwlock");

                    return Err(ServerError::Unknown);
                };

                for (_name, passkey) in keys_writer.iter_mut() {
                    if let Some(updated) = passkey.update_credential(&auth_result) {
                        did_update = updated;
                        break;
                    }
                }
            }

            if did_update {
                if let Err(err) = state.db.save() {
                    log::warn!("authentication_finish failed to save db {:?}", err);
                }
            }

            StatusCode::OK
        },
        Err(err) => {
            log::warn!("authentication_finish failed finish passkey authentication {:?}", err);

            StatusCode::BAD_REQUEST
        }
    };

    Ok(res)
}
