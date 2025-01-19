use crate::backend::dir::DirBackend;
use crate::backend::vec::VecBackend;
use crate::{KeyWithMetadata, MyJwkEcKey, Thumbprint};
use std::collections::HashMap;
use url::Url;

pub mod dir;
pub(crate) mod vec;

// What does a Key Source do?
// - Get all keys (adv)
// - Get one key by its thumbprint (adv/:skid),
// - Manage a key set (create/advertise/unadvertise/delete), very rare.
//
// The application should figure out what to advertise.
// It doesn't currently hide rotated keys from the default advertisement.
/// A repository backend for JWKs.
///
/// Assumed to be a very small set of keys that are frequently accessed and queried.
/// A separate cache layer can prevent the backend from being hammered.
#[allow(async_fn_in_trait, reason = "For internal use only")]
pub(crate) trait JwkStore {
    /// Retrieve a map of thumbprints to all known keys.
    ///
    /// Given a database, it might be better to avoid enumerating all keys.
    async fn get_all_keys(&self) -> Result<HashMap<Thumbprint, KeyWithMetadata>, std::io::Error>;

    /// Retrieve a key by its thumbprint.
    ///
    /// DESIGN Key usage needs to be monitored. Increment a counter when used directly?
    async fn get_key(
        &self,
        thumbprint: &Thumbprint,
    ) -> Result<Option<KeyWithMetadata>, std::io::Error>;

    /// Store a new set of sign/verify and derive keys, initially inactive to allow propagation
    /// before advertising to clients.
    async fn store_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), std::io::Error>;

    /// Enable advertising state for a particular pair of keys.
    ///
    /// Advertising should be enabled after a key has been propagated to all nodes, at least two
    /// cache periods for safety.
    async fn advertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error>;

    /// Disable advertising state for a particular pair of keys.
    ///
    /// Advertising should be disabled once a new set of keys has been created. This does not
    /// delete the keys, as they will be needed by clients that have not rotated to the new keys.
    async fn unadvertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error>;

    /// Delete a pair of sign/verify and derive keys.
    ///
    /// This will fail if the keys are actively advertised.
    async fn delete_keys(
        &mut self,
        signing_key: &Thumbprint,
        derive_key: &Thumbprint,
    ) -> Result<(), std::io::Error>;
}

// TODO Make backends and dependencies optional
/// Source for Derive and Sign/Verification keys. Uses URI's protocol for differentiation.
pub(crate) enum Backend {
    /// Internal Vec-based backend
    EphemeralVec(VecBackend),
    /// Retrieve from environment variables.
    ///
    /// If unspecified, `env://` uses `DERIVE` and `SIGN_VERIFY` by default.
    /// Alternative variables can be specified on the query string:
    /// `env://?derive=ALTERNATE_DERIVE&sign_verify=ALTERNATE_SIGN_VERIFY`
    Env,
    /// Retrieve from a particular directory. Specified with `file:///path/to/dir`
    Directory(DirBackend),
    /// Retrieve from a Sqlite database. Supports in-memory databases for ephemeral testing.
    /// Specify with `sqlite:///path/to/file` or `sqlite::memory:`
    Sqlite,
    /// Specify with `postgres://server/table`
    Postgres,
    /// Specify with `mssql://server/table`
    MsSqlServer,
    /// Specify with `dynamodb://table-name`
    DynamoDb,
    /// Retrieve from AWS Secrets Manager. Expects a secret that contains a list of derive and sign/verify keys.
    ///
    /// Specify with `asm://secret_name`
    AwsSecretsManager,
}

impl Backend {
    pub fn for_url(url: &Url) -> Result<Backend, std::io::Error> {
        use Backend::*;
        match url.scheme() {
            "env" => Ok(Env),
            "file" => Ok(Directory(DirBackend::new(url)?)),
            "sqlite" => Ok(Sqlite),
            "postgres" => Ok(Postgres),
            "mssql" => Ok(MsSqlServer),
            "dynamodb" => Ok(DynamoDb),
            "asm" => Ok(AwsSecretsManager),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unknown backend scheme: {}", url.scheme()),
            )),
        }
    }
}
