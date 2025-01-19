//! Ephemeral in-memory backend that stores a list of keys in a vec.

use crate::backend::JwkStore;
use crate::{KeyWithMetadata, MyJwkEcKey, Thumbprint};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

pub(crate) struct VecBackend {
    pub(crate) keys: HashMap<Thumbprint, KeyWithMetadata>,
}

impl From<Vec<MyJwkEcKey>> for VecBackend {
    fn from(keys: Vec<MyJwkEcKey>) -> Self {
        let keys: HashMap<Thumbprint, KeyWithMetadata> = keys
            .into_iter()
            .map(|key| {
                let metadata = KeyWithMetadata::from(key);
                (metadata.thumbprint.clone(), metadata)
            })
            .collect();

        Self { keys }
    }
}

impl JwkStore for VecBackend {
    async fn get_all_keys(&self) -> Result<HashMap<Thumbprint, KeyWithMetadata>, Error> {
        Ok(self.keys.clone())
    }

    async fn get_key(&self, thumbprint: &Thumbprint) -> Result<Option<KeyWithMetadata>, Error> {
        let Some(key_metadata) = self.keys.get(thumbprint) else {
            return Err(Error::new(ErrorKind::NotFound, "Thumbprint not found."));
        };
        Ok(Some(key_metadata.clone()))
    }

    async fn store_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), Error> {
        let metadata = KeyWithMetadata::from(signing_key);
        self.keys.insert(metadata.thumbprint.clone(), metadata);

        let metadata = KeyWithMetadata::from(derive_key);
        self.keys.insert(metadata.thumbprint.clone(), metadata);

        Ok(())
    }

    async fn advertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), Error> {
        if !self.keys.contains_key(signing_thumbprint) {
            return Err(Error::new(
                ErrorKind::Other,
                "Signing Key for thumbprint not found",
            ));
        }

        if !self.keys.contains_key(derive_thumbprint) {
            return Err(Error::new(
                ErrorKind::Other,
                "Derive Key for thumbprint not found",
            ));
        }

        self.keys
            .get_mut(signing_thumbprint)
            .map(|k| k.advertise = true);
        self.keys
            .get_mut(derive_thumbprint)
            .map(|k| k.advertise = true);

        Ok(())
    }

    async fn unadvertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), Error> {
        if !self.keys.contains_key(signing_thumbprint) {
            return Err(Error::new(
                ErrorKind::Other,
                "Signing Key for thumbprint not found",
            ));
        }

        if !self.keys.contains_key(derive_thumbprint) {
            return Err(Error::new(
                ErrorKind::Other,
                "Derive Key for thumbprint not found",
            ));
        }

        self.keys
            .get_mut(signing_thumbprint)
            .map(|k| k.advertise = false);
        self.keys
            .get_mut(derive_thumbprint)
            .map(|k| k.advertise = false);

        Ok(())
    }

    async fn delete_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), Error> {
        if !self.keys.contains_key(signing_thumbprint) {
            return Err(Error::new(
                ErrorKind::Other,
                "Signing Key for thumbprint not found",
            ));
        }

        if !self.keys.contains_key(derive_thumbprint) {
            return Err(Error::new(
                ErrorKind::Other,
                "Derive Key for thumbprint not found",
            ));
        }

        self.keys.remove(signing_thumbprint);
        self.keys.remove(derive_thumbprint);

        Ok(())
    }
}
