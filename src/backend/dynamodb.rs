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
use aws_sdk_dynamodb::types::AttributeValue::{Null, Ss, S};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType,
    ProvisionedThroughput, ScalarAttributeType,
};
use aws_sdk_dynamodb::Client;
use log::{debug, info};
use std::collections::{HashMap, HashSet};
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
        if !url.scheme().eq_ignore_ascii_case("dynamodb") {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Scheme must be dynamodb://",
            ));
        }

        // Use default table name if not supplied
        let mut table = match url.path_segments() {
            None => Self::DEFAULT_TABLE_NAME,
            Some(mut segments) => segments.next().unwrap_or(Self::DEFAULT_TABLE_NAME),
        };

        if table == "/" || table.is_empty() {
            table = Self::DEFAULT_TABLE_NAME;
        }

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
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        format!("Failure while looking up table {table}: {e}"),
                    ));
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
        let scan = self
            .client
            .scan()
            .table_name(self.table.clone())
            .send()
            .await
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err.to_string()))?;

        debug!("Found {} keys", scan.count());
        let mut map = HashMap::new();

        for item in scan.items.into_iter().flatten() {
            let key = MyJwkEcKey::try_from(item).map_err(|err| {
                dbg!(&err);
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Failed to deserialize key from database",
                )
            })?;

            let key = KeyWithMetadata::from(key);
            map.insert(key.thumbprint.clone(), key);
        }

        // Return empty list for now
        Ok(map)
    }

    async fn get_key(
        &self,
        thumbprint: &Thumbprint,
    ) -> Result<Option<KeyWithMetadata>, std::io::Error> {
        if thumbprint.is_empty() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Key Thumbprint cannot be empty",
            ));
        }

        let res = self
            .client
            .get_item()
            .table_name(self.table.clone())
            .key("thumbprint", S(thumbprint.to_string()))
            .send()
            .await
            .map_err(|err| {
                std::io::Error::new(
                    ErrorKind::NotFound,
                    format!("Failed to retrieve key for thumbprint {thumbprint}: {err}"),
                )
            })?;

        let Some(item) = res.item else {
            return Ok(None);
        };

        let key = MyJwkEcKey::try_from(item).map_err(|err| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("Failed to deserialize key {thumbprint} from database"),
            )
        })?;

        let key = KeyWithMetadata::from(key);

        Ok(Some(key))
    }

    async fn store_keys(
        &mut self,
        signing_key: MyJwkEcKey,
        derive_key: MyJwkEcKey,
    ) -> Result<(), std::io::Error> {
        // TODO Wrap in a transaction

        use AttributeValue::*;
        let put_signing = self
            .client
            .put_item()
            .table_name(self.table.clone())
            .set_item(Some(signing_key.into()))
            .send()
            .await
            .map_err(|err| {
                std::io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to store Signing Key: {err:?}"),
                )
            })?;

        let put_derive = self
            .client
            .put_item()
            .table_name(self.table.clone())
            .set_item(Some(derive_key.into()))
            .send()
            .await
            .map_err(|err| {
                std::io::Error::new(
                    ErrorKind::Other,
                    format!("Failed to store Derive Key: {err:?}"),
                )
            })?;

        Ok(())
    }

    async fn advertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!("Set advertise to true for a pair of keys")
    }

    async fn unadvertise_keys(
        &mut self,
        signing_thumbprint: &Thumbprint,
        derive_thumbprint: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!("Set advertise to false for a pair of keys")
    }

    async fn delete_keys(
        &mut self,
        signing_key: &Thumbprint,
        derive_key: &Thumbprint,
    ) -> Result<(), std::io::Error> {
        // Use a transaction
        todo!("Delete a pair of keys")
    }
}

impl TryFrom<HashMap<String, AttributeValue>> for MyJwkEcKey {
    type Error = anyhow::Error;

    fn try_from(map: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        let crv = match map.get("crv") {
            Some(S(crv)) => crv.clone(),
            Some(_) => bail!("Map contains crv, but it is not a String"),
            _ => bail!("Map does not contain crv"),
        };

        let x = match map.get("x") {
            Some(S(x)) => x.clone(),
            Some(_) => bail!("Map contains x, but it is not a String"),
            _ => bail!("Map does not contain x"),
        };

        let y = match map.get("y") {
            Some(S(y)) => y.clone(),
            Some(_) => bail!("Map contains y, but it is not a String"),
            _ => bail!("Map does not contain y"),
        };

        let d = match map.get("d") {
            Some(S(d)) => Some(d.clone()),
            Some(_) => bail!("Map contains d, but it is not a String"),
            None => None,
        };

        let kty = match map.get("kty") {
            Some(S(kty)) => kty.clone(),
            Some(_) => bail!("Map contains kty, but it is not a String"),
            _ => bail!("Map does not contain kty"),
        };

        let r#use = match map.get("use") {
            Some(S(r#use)) => Some(r#use.clone()),
            Some(Null(true)) => None,
            Some(_) => bail!("Map contains use, but it is not a String"),
            None => None,
        };

        let key_ops = match map.get("key_ops") {
            Some(Ss(key_ops)) => HashSet::from_iter(key_ops.iter().map(|k| k.to_string())),
            Some(_) => bail!("Map contains key_ops, but it is not a String Set"),
            None => HashSet::new(),
        };

        let alg = match map.get("alg") {
            Some(S(alg)) => Some(alg.clone()),
            Some(_) => bail!("Map contains alg, but it is not a String"),
            None => bail!("Map does not contain alg"),
        };

        let kid = match map.get("kid") {
            Some(S(id)) => Some(id.clone()),
            Some(Null(true)) => None,
            Some(_) => bail!("Map contains kid, but it is not a String"),
            None => None,
        };

        // Unused fields
        let x5u = match map.get("x5u") {
            Some(S(x5u)) => Some(x5u.clone()),
            Some(Null(true)) => None,
            Some(_) => bail!("Map contains x5u, but it is not a String"),
            None => None,
        };

        let x5c = match map.get("x5c") {
            Some(S(x5c)) => Some(x5c.clone()),
            Some(Null(true)) => None,
            Some(_) => bail!("Map contains x5c, but it is not a String"),
            None => None,
        };

        let x5t = match map.get("x5t") {
            Some(S(x5t)) => Some(x5t.clone()),
            Some(Null(true)) => None,
            Some(_) => bail!("Map contains x5t, but it is not a String"),
            None => None,
        };

        let x5t_s256 = match map.get("x5t_s256") {
            Some(S(x5t_s256)) => Some(x5t_s256.clone()),
            Some(Null(true)) => None,
            Some(_) => bail!("Map contains x5t_s256, but it is not a String"),
            None => None,
        };

        Ok(Self {
            crv,
            x,
            y,
            d,
            kty,
            r#use,
            key_ops,
            alg,
            kid,
            x5u,
            x5c,
            x5t,
            x5t_s256,
        })
    }
}

impl Into<HashMap<String, AttributeValue>> for MyJwkEcKey {
    fn into(self) -> HashMap<String, AttributeValue> {
        let mut map = HashMap::new();
        map.insert("thumbprint".to_string(), S(self.thumbprint()));
        map.insert("crv".to_string(), S(self.crv));
        map.insert("x".to_string(), S(self.x));
        map.insert("y".to_string(), S(self.y));
        map.insert(
            "d".to_string(),
            match self.d {
                None => Null(true),
                Some(d) => S(d),
            },
        );
        map.insert("kty".to_string(), S(self.kty));
        map.insert(
            "use".to_string(),
            match self.r#use {
                None => Null(true),
                Some(r#use) => S(r#use),
            },
        );
        map.insert(
            "key_ops".to_string(),
            Ss(self.key_ops.into_iter().collect::<Vec<_>>()),
        );
        map.insert(
            "alg".to_string(),
            match self.alg {
                None => Null(true),
                Some(alg) => S(alg),
            },
        );
        map.insert(
            "kid".to_string(),
            match self.kid {
                None => Null(true),
                Some(kid) => S(kid),
            },
        );
        map.insert(
            "x5u".to_string(),
            match self.x5u {
                None => Null(true),
                Some(x5u) => S(x5u),
            },
        );
        map.insert(
            "x5c".to_string(),
            match self.x5c {
                None => Null(true),
                Some(x5c) => S(x5c),
            },
        );
        map.insert(
            "x5t".to_string(),
            match self.x5t {
                None => Null(true),
                Some(x5t) => S(x5t),
            },
        );
        map.insert(
            "x5t_s256".to_string(),
            match self.x5t_s256 {
                None => Null(true),
                Some(x5t_s256) => S(x5t_s256),
            },
        );

        map
    }
}
