use crate::backend::JwkStore;
use crate::{KeyWithMetadata, MyJwkEcKey, Thumbprint};
use aws_sdk_dynamodb::operation::describe_table::DescribeTableOutput;
use aws_sdk_dynamodb::Client;
use std::collections::HashMap;
use std::io::Error;

pub(crate) struct DynamoDbStore {
    client: Client,
    table: String,
}

impl DynamoDbStore {
    pub(crate) async fn new(client: &Client, table: &str) -> anyhow::Result<Self> {
        // Check if table exists
        let DescribeTableOutput { table, .. } =
            client.describe_table().table_name(table).send().await?;
        if table.is_none() {
            // Create table
        }

        todo!()
    }
}

impl JwkStore for DynamoDbStore {
    async fn get_all_keys(&self) -> Result<HashMap<Thumbprint, KeyWithMetadata>, Error> {
        todo!()
    }

    async fn get_key(&self, thumbprint: &Thumbprint) -> Result<Option<KeyWithMetadata>, Error> {
        todo!()
    }

    async fn store_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), Error> {
        todo!()
    }

    async fn advertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), Error> {
        todo!()
    }

    async fn unadvertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), Error> {
        todo!()
    }

    async fn delete_keys(
        &mut self,
        signing_key: &Thumbprint,
        derive_key: &Thumbprint,
    ) -> Result<(), Error> {
        todo!()
    }
}
