/*
use ctap_hid_fido2::HidInfo;

fn print_hid_devices(list: &[HidInfo]) {
    for dev in list {
        println!("hid device:\n\tpid={:04x}\n\tvid={:04x}\n\tproduct={}\n\tinfo={}", dev.pid, dev.vid, dev.product_string, dev.info);

        match &dev.param {
            ctap_hid_fido2::HidParam::Path(path) => {
                println!("\tparam={}", path);
            }
            _ => {}
        }
    }
}

fn main() {
    let cfg = ctap_hid_fido2::LibCfg::init();
    let fido_keys = ctap_hid_fido2::get_fidokey_devices();

    if fido_keys.len() == 0 {
        println!("no fido keys found");

        let devices = ctap_hid_fido2::get_hid_devices();

        if devices.is_empty() {
            println!("no hid's found");

            return;
        }

        print_hid_devices(&devices);

        return;
    }

    print_hid_devices(&fido_keys);
}
*/
use std::sync::mpsc::{channel, RecvError, Sender};
use std::thread::JoinHandle;
use std::thread;

use url::Url;
use webauthn_rs_core::proto::{CreationChallengeResponse, RegisterPublicKeyCredential, Base64UrlSafeData, AuthenticatorAttestationResponseRaw, RequestChallengeResponse, PublicKeyCredential, AuthenticatorAssertionResponseRaw};
use authenticator::ctap2::client_data::{CollectedClientData, Challenge, WebauthnType};
use authenticator::statecallback::StateCallback;
use authenticator::authenticatorservice::{RegisterArgs, AuthenticatorService, SignArgs};
use authenticator::ctap2::server::{ResidentKeyRequirement, UserVerificationRequirement, AuthenticationExtensionsClientInputs, CredentialProtectionPolicy, RelyingParty, PublicKeyCredentialUserEntity, PublicKeyCredentialParameters, PublicKeyCredentialDescriptor, Transport};
use authenticator::{StatusUpdate, StatusPinUv, Pin};
use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
struct AppArgs {
    #[arg(long)]
    host: Option<String>,
    #[arg(short = 'p', long)]
    port: Option<u16>,
    #[arg(short = 's', long)]
    secure: bool,

    #[command(subcommand)]
    action: Action
}

#[derive(Args)]
struct RegisterAction {
    #[arg(short = 'u', long)]
    username: String,
    #[arg(short = 'k', long)]
    key_name: String,
}

#[derive(Args)]
struct AuthenticateAction {
    #[arg(short = 'u', long)]
    username: String,
}

#[derive(Subcommand)]
enum Action {
    #[command()]
    Ping,
    Register(RegisterAction),
    Authenticate(AuthenticateAction)
}

fn create_registration_args(url: &Url, ccr: CreationChallengeResponse) -> (RegisterArgs, CollectedClientData, u64) {
    use webauthn_rs_core::proto::{AuthenticatorTransport, UserVerificationPolicy};

    let collected_client_data = CollectedClientData {
        webauthn_type: WebauthnType::Create,
        challenge: Challenge::new(ccr.public_key.challenge.0),
        origin: String::from("https://webauthn.dac098.com/"),
        cross_origin: false,
        token_binding: None
    };

    let timeout = ccr.public_key.timeout.unwrap_or(30 * 1_000) as u64;
    let client_data_hash = collected_client_data.hash()
        .expect("failed generating hash for collected client data")
        .0;
    let relying_party = RelyingParty {
        id: ccr.public_key.rp.id,
        name: Some(ccr.public_key.rp.name)
    };
    let origin = url.to_string();
    let user = PublicKeyCredentialUserEntity {
        id: ccr.public_key.user.id.0,
        name: Some(ccr.public_key.user.name),
        display_name: Some(ccr.public_key.user.display_name)
    };
    let pub_cred_params = ccr.public_key.pub_key_cred_params.into_iter()
        .filter_map(|param| {
            match param.type_.as_str() {
                "public-key" => {
                    if let Ok(alg) = param.alg.try_into() {
                        Some(PublicKeyCredentialParameters { alg })
                    } else {
                        None
                    }
                }
                _ => None
            }
        })
        .collect();
    let exclude_list = ccr.public_key.exclude_credentials.unwrap_or_default()
        .into_iter()
        .map(|v| {
            PublicKeyCredentialDescriptor {
                id: v.id.0,
                transports: v.transports.unwrap_or_default()
                    .into_iter()
                    .filter_map(|t| {
                        match t {
                            AuthenticatorTransport::Ble => Some(Transport::BLE),
                            AuthenticatorTransport::Usb => Some(Transport::USB),
                            AuthenticatorTransport::Nfc => Some(Transport::NFC),
                            AuthenticatorTransport::Internal => Some(Transport::Internal),
                            _ => None
                        }
                    })
                    .collect()
            }
        })
        .collect();

    let user_verification_req;
    let resident_key_req;

    if let Some(auth_sele) = ccr.public_key.authenticator_selection {
        user_verification_req = match auth_sele.user_verification {
            UserVerificationPolicy::Discouraged_DO_NOT_USE => UserVerificationRequirement::Discouraged,
            UserVerificationPolicy::Preferred => UserVerificationRequirement::Preferred,
            UserVerificationPolicy::Required => UserVerificationRequirement::Required,
        };
        resident_key_req = if auth_sele.require_resident_key {
            ResidentKeyRequirement::Required
        } else {
            ResidentKeyRequirement::Discouraged
        };
    } else {
        user_verification_req = UserVerificationRequirement::Preferred;
        resident_key_req = ResidentKeyRequirement::Discouraged;
    };

    let mut extensions = AuthenticationExtensionsClientInputs::default();

    if let Some(ext) = ccr.public_key.extensions {
        if let Some(cred_protect) = ext.cred_protect {
            extensions.credential_protection_policy = Some(match cred_protect.credential_protection_policy {
                webauthn_rs_core::proto::CredentialProtectionPolicy::UserVerificationOptional =>
                    CredentialProtectionPolicy::UserVerificationOptional,
                webauthn_rs_core::proto::CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList =>
                    CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
                webauthn_rs_core::proto::CredentialProtectionPolicy::UserVerificationRequired =>
                    CredentialProtectionPolicy::UserVerificationRequired
            });
            extensions.enforce_credential_protection_policy = cred_protect.enforce_credential_protection_policy;
        }

        extensions.cred_props = ext.cred_props;
        extensions.min_pin_length = ext.min_pin_length;
        extensions.hmac_create_secret = ext.hmac_create_secret;
    }

    let register_args = RegisterArgs {
        client_data_hash,
        relying_party,
        origin,
        user,
        pub_cred_params,
        exclude_list,
        user_verification_req,
        resident_key_req,
        extensions,
        pin: None,
        use_ctap1_fallback: false
    };

    (register_args, collected_client_data, timeout)
}

fn create_authentication_args(url: &Url, rcr: RequestChallengeResponse) -> (SignArgs, CollectedClientData, u64) {
    use webauthn_rs_core::proto::{AuthenticatorTransport, UserVerificationPolicy};

    let collected_client_data = CollectedClientData {
        webauthn_type: WebauthnType::Get,
        challenge: Challenge::new(rcr.public_key.challenge.0),
        origin: String::from("https://webauthn.dac098.com"),
        cross_origin: false,
        token_binding: None
    };

    let timeout = rcr.public_key.timeout.unwrap_or(30 * 1000) as u64;
    let client_data_hash = collected_client_data.hash()
        .expect("failed generating hash for collected client data")
        .0;
    let relying_party_id = rcr.public_key.rp_id;
    let origin = url.to_string();
    let user_verification_req = match rcr.public_key.user_verification {
        UserVerificationPolicy::Discouraged_DO_NOT_USE => UserVerificationRequirement::Discouraged,
        UserVerificationPolicy::Preferred => UserVerificationRequirement::Preferred,
        UserVerificationPolicy::Required => UserVerificationRequirement::Required
    };
    let allow_list = rcr.public_key.allow_credentials.into_iter()
        .filter_map(|v| {
            match v.type_.as_str() {
                "public-key" => Some(PublicKeyCredentialDescriptor {
                    id: v.id.0,
                    transports: v.transports.unwrap_or_default()
                        .into_iter()
                        .filter_map(|t| match t {
                            AuthenticatorTransport::Ble => Some(Transport::BLE),
                            AuthenticatorTransport::Usb => Some(Transport::USB),
                            AuthenticatorTransport::Nfc => Some(Transport::NFC),
                            AuthenticatorTransport::Internal => Some(Transport::Internal),
                            _ => None
                        })
                        .collect()
                }),
                _ => None
            }
        })
        .collect();
    let mut extensions = AuthenticationExtensionsClientInputs::default();

    if let Some(ext) = rcr.public_key.extensions {
        extensions.app_id = ext.appid;
    }

    let sign_args = SignArgs {
        client_data_hash,
        origin,
        relying_party_id,
        allow_list,
        user_verification_req,
        user_presence_req: true,
        extensions,
        pin: None,
        use_ctap1_fallback: false
    };

    (sign_args, collected_client_data, timeout)
}

fn spawn_status_thread() -> (JoinHandle<()>, Sender<StatusUpdate>) {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let status_thread = thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::InteractiveManagement(_)) => {
                panic!("STATUS: this can't happen when doing non-iteractive usage");
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                println!("STATUS: please select a device by touching one of them.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                println!("STATUS: waiting for user presence");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                let raw_pin = rpassword::prompt_password("Enter PIN: ")
                    .expect("failed to read pin");

                sender.send(Pin::new(&raw_pin)).expect("failed to send pin");

                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                println!(
                    "STATUS: Wrong PIN {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );

                let raw_pin = rpassword::prompt_password("Enter PIN: ")
                    .expect("failed to read pin");

                sender.send(Pin::new(&raw_pin)).expect("failed to send pin");

                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                panic!("STATUS: Too many failed attempts in one row. Your device has been temporarily blocked. Please unplug it and plug it again.");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                panic!("STATUS: Too many failed attempts. Your device has been blocked. Reset it.")
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts))) => {
                println!(
                    "STATUS: Wrong UV! {}",
                    attempts.map_or("Try again.".to_string(), |a| format!(
                        "You have {a} attempts left."
                    ))
                );

                continue;
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::UvBlocked)) => {
                println!("STATUS: Too many failed UV-attempts");

                continue;
            }
            Ok(StatusUpdate::PinUvError(e)) => {
                panic!("STATUS: Unexpected error: {:?}", e)
            },
            Ok(StatusUpdate::SelectResultNotice(_, _)) => {
                panic!("STATUS: Unexpected select device notice");
            }
            Err(RecvError) => {
                println!("STATUS: closing status thread");
                return;
            }
        }
    });

    (status_thread, status_tx)
}

fn ping_action(server_url: Url) {
    let url = server_url.join("/ping").unwrap();
    let result = reqwest::blocking::get(url)
        .expect("failed sending request");

    let status = result.status();

    if !status.is_success() {
        print!("[{}]", status);

        if let Ok(body) = result.text() {
            print!(" {}", body);
        }

        println!("");
    } else {
        if let Ok(body) = result.text() {
            println!("{}", body);
        } else {
            println!("unknown server response");
        }
    }
}

fn register_action(server_url: Url, reg: RegisterAction) {
    let client = reqwest::blocking::Client::builder()
        .cookie_store(true)
        .build()
        .expect("failed to build http client");

    let payload = common::NewRegistration {
        username: reg.username.into_boxed_str(),
        key_name: reg.key_name.into_boxed_str(),
    };
    let url = server_url.join("/registration/start").unwrap();
    let result = client.post(url.clone())
        .json(&payload)
        .send()
        .expect("failed sending registration start");

    let status = result.status();

    if !status.is_success() {
        print!("[{}]", status);

        if let Ok(body) = result.text() {
            print!("{}", body);
        }

        println!("");

        return;
    }

    let Ok(ccr): Result<CreationChallengeResponse, _> = result.json() else {
        panic!("failed parsing json body");
    };

    println!("ccr {:#?}", ccr);

    let (registration, client_data, timeout) = create_registration_args(&url, ccr);

    let mut manager = AuthenticatorService::new()
        .expect("failed to initialize authenticatior service");
    manager.add_u2f_usb_hid_platform_transports();

    let (_status_thread, status_tx) = spawn_status_thread();
    let credential_result;

    loop {
        let (register_tx, register_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).unwrap();
        }));

        println!("registering key");

        if let Err(err) = manager.register(timeout, registration, status_tx, callback) {
            panic!("couldn't register: {:?}", err);
        }

        let register_result = register_rx.recv()
            .expect("failed to receive registration result");

        match register_result {
            Ok(a) => {
                credential_result = a;
                break;
            }
            Err(err) => panic!("failed registration {:?}", err)
        }
    }

    println!("credential result {:?}", credential_result);

    let raw_id = Base64UrlSafeData(credential_result.att_obj.auth_data.credential_data.as_ref()
        .expect("credential data not present in attestation")
        .credential_id
        .clone());
    let client_data_json = Base64UrlSafeData(serde_json::to_vec(&client_data)
        .expect("failed generating hash for collected client data"));
    let attestation_object = Base64UrlSafeData(serde_cbor::to_vec(&credential_result.att_obj)
        .expect("failed serializing attestation object"));

    let register_public_credential = RegisterPublicKeyCredential {
        id: raw_id.to_string(),
        raw_id,
        response: AuthenticatorAttestationResponseRaw {
            attestation_object,
            client_data_json,
            transports: None
        },
        type_: "public-key".to_owned(),
        extensions: Default::default()
    };

    let url = server_url.join("/registration/finish")
        .unwrap();
    let result = client.post(url.clone())
        .json(&register_public_credential)
        .send()
        .expect("failed sending registration finish");

    let status = result.status();

    if !status.is_success() {
        print!("[{}]", status);

        if let Ok(body) = result.text() {
            print!("{}", body);
        }

        println!("");
    } else {
        println!("registered with server");
    }
}

fn authenticate_action(server_url: Url, auth: AuthenticateAction) {
    let client = reqwest::blocking::Client::builder()
        .cookie_store(true)
        .build()
        .expect("failed to build http client");

    let payload = common::NewAuthentication {
        username: auth.username.into_boxed_str()
    };
    let url = server_url.join("/authentication/start").unwrap();
    let result = client.post(url.clone())
        .json(&payload)
        .send()
        .expect("failed sending registration start");

    let status = result.status();

    if !status.is_success() {
        print!("[{}]", status);

        if let Ok(body) = result.text() {
            print!("{}", body);
        }

        println!("");

        return;
    }

    let Ok(rcr): Result<RequestChallengeResponse, _> = result.json() else {
        panic!("failed parsing json body");
    };

    println!("rcr {:#?}", rcr);

    let (authentication, client_data, timeout) = create_authentication_args(&url, rcr);

    let mut manager = AuthenticatorService::new()
        .expect("failed to initialize authenticatior service");
    manager.add_u2f_usb_hid_platform_transports();

    let (_status_thread, status_tx) = spawn_status_thread();
    let assertion_result;

    loop {
        let (sign_tx, sign_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            sign_tx.send(rv).unwrap();
        }));

        println!("authenticating key");

        if let Err(err) = manager.sign(timeout, authentication, status_tx, callback) {
            panic!("couldn't register: {:?}", err);
        }

        let sign_result = sign_rx.recv()
            .expect("failed to receive assertion result");

        match sign_result {
            Ok(a) => {
                assertion_result = a;
                break;
            }
            Err(err) => panic!("failed assertion {:?}", err)
        }
    }

    let raw_id = assertion_result.assertion.credentials.map(|v| Base64UrlSafeData(v.id))
        .expect("credential data not present in assertion");
    let user_handle = assertion_result.assertion.user.map(|v| Base64UrlSafeData(v.id));
    let signature = Base64UrlSafeData(assertion_result.assertion.signature);
    let authenticator_data = Base64UrlSafeData(assertion_result.assertion.auth_data.to_vec());
    let client_data_json = Base64UrlSafeData(serde_json::to_vec(&client_data)
        .expect("failed generating hash for collected client data"));

    let assertion_public_credential = PublicKeyCredential {
        id: raw_id.to_string(),
        raw_id,
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data,
            client_data_json,
            signature,
            user_handle
        },
        type_: "public-key".to_owned(),
        extensions: Default::default()
    };

    let url = server_url.join("/authentication/finish")
        .unwrap();
    let result = client.post(url.clone())
        .json(&assertion_public_credential)
        .send()
        .expect("failed sending authentication finish");

    let status = result.status();

    if !status.is_success() {
        print!("[{}]", status);

        if let Ok(body) = result.text() {
            print!("{}", body);
        }

        println!("");
    } else {
        println!("authenticated with server");
    }
}

fn main() {
    env_logger::init();

    let args = AppArgs::parse();
    let mut server_url = url::Url::parse("http://localhost/")
        .unwrap();

    if args.secure {
        server_url.set_scheme("https").unwrap();
    }

    if let Some(host) = args.host {
        server_url.set_host(Some(&host))
            .expect("invalid host value provided");
    }
    
    if let Some(port) = args.port {
        server_url.set_port(Some(port)).unwrap();
    }

    match args.action {
        Action::Ping => ping_action(server_url),
        Action::Register(reg) => register_action(server_url, reg),
        Action::Authenticate(auth) => authenticate_action(server_url, auth),
    }
}

/*
let Ok(reg_json): Result<CreationChallengeResponse, _> = result.json() else {
    println!("failed parsing json body");
    return;
};

println!("{:#?}", reg_json);

let Some(pubkey_reg) = reg_json["publicKey"].as_object() else {
    println!("invalid registration object. missing \"publicKey\"");
    return;
};

let exclude_list = if let Some(exclude) = pubkey_reg.get("excludeCredentials") {
    serde_json::from_value(exclude.take())
        .expect("failed deserializing excludeCredentials")
} else {
    Vec::new()
};

let user_verification_req;
let resident_key_req;
let timeout_ms;

if let Some(auth_sele) = pubkey_reg["authenticationSelection"].as_object() {
    resident_key_req = if let Some(resident_key) = auth_sele.get("residentKey") {
        if let Some(string_t) = resident_key.as_str() {
            match string_t {
                "discouraged" => ResidentKeyRequirement::Discouraged,
                "preferred" => ResidentKeyRequirement::Preferred,
                "required" => ResidentKeyRequirement::Required,
                _ => panic!("authenticationSelection.residentKey is an unknown value")
            };
        } else {
            panic!("authenticationSelection.residentKey is not a string");
        }
    } else if let Some(require_resident_key) = auth_sele.get("requireResidentKey") {
        if let Some(bool_t) = require_resident_key.as_bool() {
            if bool_t { 
                ResidentKeyRequirement::Required 
            } else {
                ResidentKeyRequirement::Discouraged
            }
        } else {
            panic!("authenticationSelection.requireResidentKey is not a bool");
        }
    } else {
        ResidentKeyRequirement::Discouraged
    };

    user_verification_req = if let Some(user_verification) = auth_sele.get("userVerification") {
        if let Some(string_t) = user_verification.as_str() {
            match string_t {
                "discouraged" => UserVerificationRequirement::Discouraged,
                "preferred" => UserVerificationRequirement::Preferred,
                "required" => UserVerificationRequirement::Required,
                _ => panic!("authenticationSelection.userVerification is an unknown value")
            }
        } else {
            panic!("authenticationSelection.userVerification is not a string")
        }
    } else {
        UserVerificationRequirement::Preferred
    };
} else {
    user_verification_req = UserVerificationRequirement::Preferred;
    resident_key_req = ResidentKeyRequirement::Discouraged;
};
let client_data_hash = if let Some(challenge) = pubkey_reg.get("challenge") {
    let string_t = challenge.as_str().expect("challenge is not a string");
    let bytes = URL_SAFE.decode(input).expect("challenge is not a valid base64 url safe string");

    let fixed: [u8; 32] = TryFrom::try_from(bytes)
        .expect("challenge contains an unexpected amount of bytes");

    fixed
} else {
    panic!("missing challenge from server");
};
let extensions = if let Some(extensions) = pubkey_reg.get("extensions") {
    let mut rtn = AuthenticationExtensionsClientInputs::default();

    if let Some(app_id) = extensions.get("appid") {
        let string_t = app_id.as_str().expect("extensions.appid is not a string");

        rtn.app_id = Some(string_t.to_owned());
    }

    if let Some(cred_props) = extensions.get("credProps") {
        let bool_t = cred_props.as_bool().expect("extensions.credProps is not a bool");

        rtn.cred_props = Some(bool_t);
    }

    if let Some(cred_protect_policy) = extensions.get("credProtect") {
        let object_t = cred_protect_policy.as_object().expect("extensions.credProtect is not an object");
        let string_t = cred_protect_policy.as_str().expect("extensions.credentialProtectionPolicy is not a string");

        rtn.credential_protection_policy = Some(match string_t {
            "userVerificationOptional" => CredentialProtectionPolicy::UserVerificationOptional,
            "userVerificationOptionalWithCredentialIDList" => CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
            "userVerificationRequired" => CredentialProtectionPolicy::UserVerificationRequired,
            _ => panic!("extensions.credProect is an unknown value")
        });
    }

    if let Some(enforce_protect_policy) = extensions.get("enforceCredentialProtectionPolicy") {
        let bool_t = enforce_protect_policy.as_bool().expect("extensions.enforceCredentialProtectionPolicy is not a bool");

        rtn.enforce_credential_protection_policy = Some(bool_t);
    }
}

let registration = RegisterArgs {
    client_data_hash,
    relying_party: serde_json::from_value(pubkey_reg["rp"].take())
        .expect("failed deserializing rp object"),
    origin: url.to_string(),
    user: serde_json::from_value(pubkey_reg["user"].take())
        .expect("failed deserializing user object"),
    pub_cred_params: serde_json::from_value(pubkey_reg["pubKeyCredParams"].take())
        .expect("failed deserializing pubKeyCredParams object"),
    exclude_list,
    user_verification_req,
    resident_key_req,
    extensions: serde_json::from_value(pubkey_reg["extensions"])
};
*/