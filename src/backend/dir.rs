use crate::backend::JwkStore;
use crate::{KeyWithMetadata, MyJwkEcKey, Thumbprint};
use std::collections::{HashMap, HashSet};
use std::io::Error;
use std::path::PathBuf;

struct DirBackend {
    path: PathBuf,
}

impl DirBackend {
    fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Key database \"{}\" does not exist", path.to_string_lossy()),
            ));
        }

        if !path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "Key database \"{}\" is not a directory",
                    path.to_string_lossy()
                ),
            ));
        }

        Ok(Self { path })
    }
}

impl JwkStore for DirBackend {
    async fn get_all_keys(&self) -> Result<HashMap<Thumbprint, KeyWithMetadata>, std::io::Error> {
        if !self.path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Key database \"{}\" does not exist",
                    self.path.to_string_lossy()
                ),
            ));
        }

        if !self.path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "Key database \"{}\" is not a directory",
                    self.path.to_string_lossy()
                ),
            ));
        }

        let jwk_files: Vec<PathBuf> = self
            .path
            .read_dir()?
            .filter_map(|f| f.ok())
            .map(|e| e.path())
            .filter(|f| f.extension() == Some(std::ffi::OsStr::new("jwk")))
            .collect();

        let keys: HashMap<Thumbprint, KeyWithMetadata> = jwk_files
            .iter()
            .filter_map(|file_path| {
                let Some(file_name) = file_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                else {
                    return None;
                };
                let advertised = file_name.starts_with('.');

                // TODO Async read for potentially larger directories
                let Ok(file_content) = std::fs::read_to_string(file_path) else {
                    return None;
                };
                let Ok(jwk) = serde_json::from_str::<MyJwkEcKey>(&file_content) else {
                    return None;
                };
                let mut metadata = KeyWithMetadata::from(jwk);
                metadata.advertise = advertised;

                // TODO Ensure that fingerprint matches filename.

                Some((metadata.thumbprint.clone(), metadata))
            })
            .collect();

        // Sanity Check for duplicate advertised and unadvertised keys.
        let mut seen_keys = HashSet::new();
        keys.keys().try_for_each(|thp| {
            if !seen_keys.insert(thp) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Key is both advertised and unadvertised: {thp}"),
                ))
            } else {
                Ok(())
            }
        })?;

        Ok(keys)
    }

    async fn get_key(
        &self,
        thumbprint: &Thumbprint,
    ) -> Result<Option<KeyWithMetadata>, std::io::Error> {
        if !self.path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "Key database \"{}\" is not a directory",
                    self.path.to_string_lossy()
                ),
            ));
        }

        let advertised = self.path.join(format!("{thumbprint}.jwk"));
        let unadvertised = self.path.join(format!(".{thumbprint}.jwk"));

        let (advertised, file_content) = if advertised.try_exists()? && advertised.is_file() {
            (true, std::fs::read_to_string(advertised)?)
        } else if unadvertised.try_exists()? && unadvertised.is_file() {
            (false, std::fs::read_to_string(&unadvertised)?)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No key found for thumbprint {thumbprint}"),
            ));
        };

        let jwk = match serde_json::from_str::<MyJwkEcKey>(&file_content) {
            Ok(jwk) => jwk,
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Could not parse key: {}", err),
                ))
            }
        };

        let mut metadata = KeyWithMetadata::from(jwk);
        metadata.advertise = advertised;

        // TODO Ensure that thumbprint matches file name.

        Ok(Some(metadata))
    }

    async fn store_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), std::io::Error> {
        let signing_thumbprint = signing_key.thumbprint();
        let signing_advertised = self.path.join(format!("{signing_thumbprint}.jwk"));
        let signing_advertised_is_file = signing_advertised.is_file();

        let signing_unadvertised = self.path.join(format!(".{signing_thumbprint}.jwk"));
        let signing_unadvertised_is_file = signing_unadvertised.is_file();

        let derive_thumbprint = derive_key.thumbprint();
        let derive_advertised = self.path.join(format!("{derive_thumbprint}.jwk"));
        let derive_advertised_is_file = derive_advertised.is_file();

        let derive_unadvertised = self.path.join(format!(".{derive_thumbprint}.jwk"));
        let derive_unadvertised_is_file = derive_unadvertised.is_file();

        // Sanity Check: Ensure that data doesn't already exist
        if signing_advertised_is_file || signing_unadvertised_is_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Signing key already exists with thumbprint {signing_thumbprint}"),
            ));
        }

        if derive_advertised_is_file || derive_unadvertised_is_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Derive key already exists with thumbprint {derive_thumbprint}"),
            ));
        }

        let signing_json = serde_json::to_string(&signing_key)?;
        let derive_json = serde_json::to_string(&derive_key)?;

        // Safe from directory traversal, thumbprint generated with
        // [a-zA-Z0-9_-] base64ct::Base64UrlUnpadded::encode_string
        std::fs::write(&signing_unadvertised, &signing_json)?;
        std::fs::write(&derive_unadvertised, &derive_json)?;

        Ok(())
    }

    async fn advertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Sanity Check: Thumbprints are well-formed url-safe base64, prevents traversal attacks.
        crate::validate_thumbprint(&signing_thumbprint)?;
        crate::validate_thumbprint(&derive_thumbprint)?;

        let signing_advertised = self.path.join(format!("{signing_thumbprint}.jwk"));
        let signing_advertised_is_file = signing_advertised.is_file();

        let signing_unadvertised = self.path.join(format!(".{signing_thumbprint}.jwk"));
        let signing_unadvertised_is_file = signing_unadvertised.is_file();

        let derive_advertised = self.path.join(format!("{derive_thumbprint}.jwk"));
        let derive_advertised_is_file = derive_advertised.is_file();

        let derive_unadvertised = self.path.join(format!(".{derive_thumbprint}.jwk"));
        let derive_unadvertised_is_file = derive_unadvertised.is_file();

        // Sanity check before move
        match (signing_advertised_is_file, signing_unadvertised_is_file) {
            (true, false) => {} // Nothing to do
            (false, true) => {} // Rename file
            (false, false) => {
                // Not found.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No keys found for thumbprint {signing_thumbprint}"),
                ));
            }
            (true, true) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Key for thumbprint {signing_thumbprint} is both advertised and unadvertised."),
                ));
            }
        }

        match (derive_advertised_is_file, derive_unadvertised_is_file) {
            (true, false) => {} // Nothing to do
            (false, true) => {} // Rename file
            (false, false) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No keys found for thumbprint {derive_thumbprint}"),
                ));
            } // Not found.
            (true, true) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Key for thumbprint {derive_thumbprint} is both advertised and unadvertised."),
                ));
            }
        }

        // Perform moves if required
        if !signing_advertised_is_file && signing_unadvertised_is_file {
            std::fs::rename(signing_unadvertised, signing_advertised)?;
        }

        if !derive_advertised_is_file && derive_unadvertised_is_file {
            std::fs::rename(derive_unadvertised, derive_advertised)?;
        }

        Ok(())
    }

    async fn unadvertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), Error> {
        // Sanity Check: Thumbprints are well-formed url-safe base64, prevents traversal attacks.
        crate::validate_thumbprint(&signing_thumbprint)?;
        crate::validate_thumbprint(&derive_thumbprint)?;

        let signing_advertised = self.path.join(format!("{signing_thumbprint}.jwk"));
        let signing_advertised_is_file = signing_advertised.is_file();

        let signing_unadvertised = self.path.join(format!(".{signing_thumbprint}.jwk"));
        let signing_unadvertised_is_file = signing_unadvertised.is_file();

        let derive_advertised = self.path.join(format!("{derive_thumbprint}.jwk"));
        let derive_advertised_is_file = derive_advertised.is_file();

        let derive_unadvertised = self.path.join(format!(".{derive_thumbprint}.jwk"));
        let derive_unadvertised_is_file = derive_unadvertised.is_file();

        // Sanity Check: Verify state of source and target files
        match (signing_advertised_is_file, signing_unadvertised_is_file) {
            (false, true) => {} // Nothing to do
            (true, false) => {} // Rename file
            (false, false) => {
                // Not found.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No keys found for thumbprint {signing_thumbprint}"),
                ));
            }
            (true, true) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Key for thumbprint {signing_thumbprint} is both advertised and unadvertised."),
                ));
            }
        }

        // Sanity Check: Verify state of source and target files
        match (derive_advertised_is_file, derive_unadvertised_is_file) {
            (false, true) => {} // Nothing to do
            (true, false) => {} // Rename file
            (false, false) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No keys found for thumbprint {derive_thumbprint}"),
                ));
            } // Not found.
            (true, true) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Key for thumbprint {derive_thumbprint} is both advertised and unadvertised."),
                ));
            }
        }

        // Perform moves if required
        if signing_advertised_is_file && !signing_unadvertised_is_file {
            std::fs::rename(signing_advertised, signing_unadvertised)?;
        }

        if derive_advertised_is_file && !derive_unadvertised_is_file {
            std::fs::rename(derive_advertised, derive_unadvertised)?;
        }

        Ok(())
    }

    async fn delete_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), std::io::Error> {
        let signing_thumbprint = signing_key.thumbprint();
        crate::validate_thumbprint(&signing_thumbprint)?;

        let signing_advertised = self.path.join(format!("{signing_thumbprint}.jwk"));
        let signing_advertised_is_file = signing_advertised.is_file();

        let signing_unadvertised = self.path.join(format!(".{signing_thumbprint}.jwk"));
        let signing_unadvertised_is_file = signing_unadvertised.is_file();

        let derive_thumbprint = derive_key.thumbprint();
        crate::validate_thumbprint(&derive_thumbprint)?;
        let derive_advertised = self.path.join(format!("{derive_thumbprint}.jwk"));
        let derive_advertised_is_file = derive_advertised.is_file();

        let derive_unadvertised = self.path.join(format!(".{derive_thumbprint}.jwk"));
        let derive_unadvertised_is_file = derive_unadvertised.is_file();

        // Sanity Check: Ensure that keys are not currently advertised.
        if signing_advertised_is_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Will not delete signing key with thumbprint {signing_thumbprint} because it is currently advertised."
                ),
            ));
        }

        if derive_advertised_is_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Will not delete derive key with thumbprint {derive_thumbprint} because it is currently advertised."
                ),
            ));
        }

        // Perform deletions
        let base_path = self.path.canonicalize()?;
        if signing_unadvertised_is_file {
            let signing_path = signing_unadvertised.canonicalize()?;
            if !signing_path.starts_with(&base_path) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Signing Key file {signing_thumbprint} does not live in keystore."),
                ));
            }
            std::fs::remove_file(signing_unadvertised)?;
        }

        if derive_unadvertised_is_file {
            let derive_path = derive_unadvertised.canonicalize()?;
            if !derive_path.starts_with(&base_path) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Derive Key file {derive_thumbprint} does not live in keystore."),
                ));
            }

            std::fs::remove_file(derive_unadvertised)?;
        }

        Ok(())
    }
}
