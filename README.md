# rust-webauthn

this is an example implementation of webauthn for a cli client and server. the client uses mozillas [`authenticator-rs`](https://github.com/mozilla/authenticator-rs) for interacting with a security key and the server uses [`webauthn-rs`](https://github.com/kanidm/webauthn-rs) for generating credentials and attestations.

currently have only tested with a Yubikey 5 and have not done anything with discoverable keys yet. the client requires administrative privilages in-order to interact with the security key otherwise the authenticator will timeout.