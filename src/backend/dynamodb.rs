//! Backend for AWS DynamoDB.
//! Test locally with `podman run --rm --name ddb -p 8000:8000 amazon/dynamodb-local`

use crate::backend::JwkStore;
use crate::{KeyWithMetadata, MyJwkEcKey, Thumbprint};
use anyhow::bail;
use aws_config::default_provider::endpoint_url;
use aws_config::{Region, SdkConfig};
use aws_sdk_dynamodb::config::BehaviorVersion;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::create_table::CreateTableOutput;
use aws_sdk_dynamodb::operation::describe_table::DescribeTableOutput;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ProvisionedThroughput,
    ScalarAttributeType,
};
use aws_sdk_dynamodb::Client;
use log::{debug, info};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::str::Split;
use url::Url;

pub(crate) struct DynamoDbStore {
    client: Client,
    table: String,
}

impl DynamoDbStore {
    const DEFAULT_TABLE_NAME: &'static str = "tldr-keys";
    pub(crate) async fn new(url: &Url) -> Result<Self, std::io::Error> {
        dbg!(&url);

        if !url.scheme().eq_ignore_ascii_case("dynamodb") {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Scheme must be dynamodb://",
            ));
        }

        let table = match url.path_segments() {
            None => Self::DEFAULT_TABLE_NAME,
            Some(mut segments) => segments.next().unwrap_or(Self::DEFAULT_TABLE_NAME),
        };

        // Look for "insecure" in the query string to allow plain HTTP connectivity.
        let insecure = url
            .query_pairs()
            .find(|(key, _)| key == "insecure")
            .is_some_and(|(_, val)| {
                dbg!(&val);
                val.eq_ignore_ascii_case("true")
            });

        let proto = match insecure {
            true => "http",
            false => "https",
        };

        // https://docs.aws.amazon.com/sdk-for-rust/latest/dg/rust_dynamodb_code_examples.html
        // Load config from environment and profile
        let mut sdk_config = aws_config::defaults(BehaviorVersion::latest());

        // Override endpoint URL if it is specified
        let endpoint_url = match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => Some(format!("{proto}://{host}:{port}")),
            (Some(host), None) => Some(format!("{proto}://{host}")),
            (_, _) => None,
        };
        if let Some(endpoint_url) = endpoint_url {
            sdk_config = sdk_config.endpoint_url(endpoint_url);
        }

        // Build config and client
        let sdk_config = sdk_config.load().await;
        let dynamodb_config = aws_sdk_dynamodb::config::Builder::from(&sdk_config).build();
        let client = Client::from_conf(dynamodb_config);

        // Try to describe table to determine if it exists. Listing tables requires broader
        // visibility into the account.
        // let tables = client.list_tables().send().await;
        let table_check = client.describe_table().table_name(table).send().await;
        let table_exists = match table_check {
            Ok(_table_output) => true,
            Err(SdkError::ServiceError(err)) => {
                let e = err.into_err();
                // If the table is missing, go ahead and create it
                if !e.is_resource_not_found_exception() {
                    return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
                }

                false
            }
            Err(SdkError::DispatchFailure(err)) => {
                // Failed to connect to service
                return Err(std::io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to connect to service: {err:?}"),
                ));
            }
            Err(err) => {
                // Failed to connect to service
                return Err(std::io::Error::new(
                    ErrorKind::Other,
                    format!("Service failure: {}", err.to_string()),
                ));
            }
        };

        if table.is_empty() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Table name is empty",
            ));
        }

        if table_exists {
            debug!("Table exists, successfully described table {table}");
        } else {
            debug!("Could not describe table {table}, attempting to create.");
            Self::create_table(&client, table).await.map_err(|err| {
                std::io::Error::new(ErrorKind::Other, format!("Failed to create table: {err:?}"))
            })?;
            info!(
                "Created table {table} in region {:?}",
                client.config().region()
            );
        }

        Ok(Self {
            client,
            table: table.to_string(),
        })
    }

    /// Create a new DynamoDB table.
    ///
    /// The table definition uses the thumbprint as a key, and is equivalent to:
    /// ```json
    /// {
    ///   "TableDescription": {
    ///     "TableName": "{table}",
    ///     "BillingMode": "PAY_PER_REQUEST",
    ///     "AttributeDefinitions": [
    ///       {
    ///         "AttributeName": "thumbprint","AttributeType": "S"
    ///       }
    ///     ],
    ///     "KeySchema": [
    ///       {
    ///         "AttributeName": "thumbprint","KeyType": "HASH"
    ///       }
    ///     ],
    ///     "ProvisionedThroughput": {
    ///       "ReadCapacityUnits": 1,"WriteCapacityUnits": 1
    ///     },
    ///     "TableClassSummary": {
    ///       "TableClass": "STANDARD"
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Based on the [CreateTable example](https://github.com/awsdocs/aws-doc-sdk-examples/blob/main/rustv1/examples/dynamodb/src/scenario/create.rs#L12)
    async fn create_table(client: &Client, table: &str) -> anyhow::Result<CreateTableOutput> {
        let key_attribute_name = "thumbprint";
        let attribute_def = AttributeDefinition::builder()
            .attribute_name(key_attribute_name)
            .attribute_type(ScalarAttributeType::S)
            .build()?;

        let key_schema = KeySchemaElement::builder()
            .key_type(KeyType::Hash)
            .attribute_name(key_attribute_name)
            .build()?;

        let res = client
            .create_table()
            .table_name(table)
            .billing_mode(BillingMode::PayPerRequest)
            .key_schema(key_schema)
            .attribute_definitions(attribute_def)
            .send()
            .await?;

        Ok(res)
    }
}

impl JwkStore for DynamoDbStore {
    async fn get_all_keys(&self) -> Result<HashMap<Thumbprint, KeyWithMetadata>, std::io::Error> {
        // Scan
        todo!()
    }

    async fn get_key(
        &self,
        thumbprint: &Thumbprint,
    ) -> Result<Option<KeyWithMetadata>, std::io::Error> {
        // Fetch key
        todo!()
    }

    async fn store_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!()
    }

    async fn advertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!()
    }

    async fn unadvertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!()
    }

    async fn delete_keys(
        &mut self,
        signing_key: &Thumbprint,
        derive_key: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!()
    }
}
