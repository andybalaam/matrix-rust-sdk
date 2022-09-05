// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unused)] // TODO

use std::{
    any::Any,
    collections::{BTreeMap, HashMap, HashSet},
    convert::{TryFrom, TryInto},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use dashmap::DashSet;
use futures_util::FutureExt;
use matrix_sdk_common::locks::Mutex;
//use tracing::debug;
use matrix_sdk_crypto::{
    olm::{
        IdentityKeys, InboundGroupSession, OutboundGroupSession, PickledInboundGroupSession,
        PickledSession, PrivateCrossSigningIdentity, Session,
    },
    store::{
        caches::SessionStore, BackupKeys, Changes, CryptoStore, CryptoStoreError, PickleKey,
        RecoveryKey, Result, RoomKeyCounts,
    },
    GossipRequest, LocalTrust, ReadOnlyAccount, ReadOnlyDevice, ReadOnlyUserIdentities, SecretInfo,
};
use matrix_sdk_store_encryption::StoreCipher;
// vdmc use olm_rs::{account::IdentityKeys, PicklingMode};
//use serde::{Deserialize, Serialize};
//pub use sled::Error;
//use sled::{
//    transaction::{ConflictableTransactionError, TransactionError},
//    Config, Db, IVec, Transactional, Tree,
//};
use redis::{
    aio::Connection, AsyncCommands, Client, ConnectionInfo, FromRedisValue, RedisConnectionInfo,
    RedisError, RedisFuture, RedisResult, ToRedisArgs,
};
use ruma::{
    events::{room_key_request::RequestedKeyInfo, secret::request::SecretName},
    DeviceId, OwnedDeviceId, OwnedUserId, RoomId, TransactionId, UserId,
};
use serde::{Deserialize, Serialize};

use crate::redis_shim::{RedisClientShim, RedisConnectionShim};
//use crate::olm::PrivateCrossSigningIdentity;

/// This needs to be 32 bytes long since AES-GCM requires it, otherwise we will
/// panic once we try to pickle a Signing object.
const DEFAULT_PICKLE: &str = "DEFAULT_PICKLE_PASSPHRASE_123456";
//const DATABASE_VERSION: u8 = 3;

// TODO: use this everywhere we manually find a key
trait RedisKey {
    fn redis_key(&self) -> String;
}

impl RedisKey for TransactionId {
    fn redis_key(&self) -> String {
        self.to_string()
    }
}

impl RedisKey for SecretName {
    fn redis_key(&self) -> String {
        self.to_string()
    }
}

impl RedisKey for SecretInfo {
    fn redis_key(&self) -> String {
        match self {
            SecretInfo::KeyRequest(k) => k.redis_key(),
            SecretInfo::SecretRequest(s) => s.redis_key(),
        }
    }
}

impl RedisKey for &RequestedKeyInfo {
    fn redis_key(&self) -> String {
        format!("{}|{}|{}|{}|", self.room_id, self.sender_key, self.algorithm, self.session_id)
    }
}

/*impl RedisKey for &UserId {
    fn redis_key(&self) -> Vec<u8> {
        self.as_str().redis_key()
    }
}

impl RedisKey for &ReadOnlyDevice {
    fn redis_key(&self) -> Vec<u8> {
        (self.user_id().as_str(), self.device_id().as_str()).redis_key()
    }
}

impl RedisKey for &RoomId {
    fn redis_key(&self) -> Vec<u8> {
        self.as_str().redis_key()
    }
}

impl RedisKey for &str {
    fn redis_key(&self) -> Vec<u8> {
        [self.as_bytes(), &[Self::SEPARATOR]].concat()
    }
}

impl RedisKey for (&str, &str) {
    fn redis_key(&self) -> Vec<u8> {
        [self.0.as_bytes(), &[Self::SEPARATOR], self.1.as_bytes(), &[Self::SEPARATOR]].concat()
    }
}

impl RedisKey for (&str, &str, &str) {
    fn redis_key(&self) -> Vec<u8> {
        [
            self.0.as_bytes(),
            &[Self::SEPARATOR],
            self.1.as_bytes(),
            &[Self::SEPARATOR],
            self.2.as_bytes(),
            &[Self::SEPARATOR],
        ]
        .concat()
    }
}*/

// TODO: maybe we should do something similar to the above to standardise the
//       keys for Redis

#[derive(Clone, Debug)]
pub struct AccountInfo {
    user_id: Arc<UserId>,
    device_id: Arc<DeviceId>,
    identity_keys: Arc<IdentityKeys>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrackedUser {
    user_id: OwnedUserId,
    dirty: bool,
}

/// A store that holds its information in a Redis database
#[derive(Clone)]
pub struct RedisStore<C>
where
    C: RedisClientShim,
{
    key_prefix: String,
    client: C,
    account_info: Arc<RwLock<Option<AccountInfo>>>,
    store_cipher: Option<Arc<StoreCipher>>,

    session_cache: SessionStore,
    tracked_users_cache: Arc<DashSet<OwnedUserId>>,
    users_for_key_query_cache: Arc<DashSet<OwnedUserId>>,
    /*    account: Tree,
     *    private_identity: Tree,
     *
     *    olm_hashes: Tree,
     *    sessions: Tree,
     *    inbound_group_sessions: Tree,
     *    outbound_group_sessions: Tree,
     *
     *    outgoing_secret_requests: Tree,
     *    unsent_secret_requests: Tree,
     *    secret_requests_by_info: Tree,
     *
     *    devices: Tree,
     *    identities: Tree,
     *
     *    tracked_users: Tree, */
}

impl<C> std::fmt::Debug for RedisStore<C>
where
    C: RedisClientShim,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStore")
            .field("redis_url", &self.client.get_connection_info().redis)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

//impl From<TransactionError<serde_json::Error>> for CryptoStoreError {
//    fn from(e: TransactionError<serde_json::Error>) -> Self {
//        match e {
//            TransactionError::Abort(e) => CryptoStoreError::Serialization(e),
//            TransactionError::Storage(e) => CryptoStoreError::Database(e),
//        }
//    }
//}

impl<C> RedisStore<C>
where
    C: RedisClientShim,
{
    #[allow(dead_code)]
    /// Open the Redis-based cryptostore at the given URL using the given
    /// passphrase to encrypt private data.
    pub async fn open_with_passphrase(client: C, passphrase: Option<&str>) -> Result<Self> {
        Self::open(client, passphrase, String::from("matrix-sdk-crypto|")).await
    }

    /// Open the Redis-based cryptostore at the given URL using the given
    /// passphrase to encrypt private data and assuming all Redis keys are
    /// prefixed with the given string.
    pub async fn open(client: C, passphrase: Option<&str>, key_prefix: String) -> Result<Self> {
        // TODO: allow supplying an additional prefix for your Redis keys
        let mut connection = client.get_async_connection().await.unwrap();

        let store_cipher = if let Some(passphrase) = passphrase {
            Some(
                Self::get_or_create_store_cipher(passphrase, &key_prefix, &mut connection)
                    .await?
                    .into(),
            )
        } else {
            None
        };

        Ok(Self {
            key_prefix,
            client,
            account_info: RwLock::new(None).into(),
            store_cipher,
            session_cache: SessionStore::new(),
            tracked_users_cache: Arc::new(DashSet::new()),
            users_for_key_query_cache: Arc::new(DashSet::new()),
        })
    }

    //    /// Create a sled based cryptostore using the given sled database.
    //    /// The given passphrase will be used to encrypt private data.
    //    pub fn open_with_database(db: Db, passphrase: Option<&str>) ->
    // Result<Self> {        RedisStore::open_helper(db, None, passphrase)
    //    }

    fn get_account_info(&self) -> Option<AccountInfo> {
        self.account_info.read().unwrap().clone()
    }

    fn serialize_value(&self, event: &impl Serialize) -> Result<Vec<u8>, CryptoStoreError> {
        if let Some(key) = &self.store_cipher {
            key.encrypt_value(event).map_err(|e| CryptoStoreError::Backend(Box::new(e)))
        } else {
            Ok(serde_json::to_vec(event)?)
        }
    }

    fn deserialize_value<T: for<'b> Deserialize<'b>>(
        &self,
        event: &[u8],
    ) -> Result<T, CryptoStoreError> {
        if let Some(key) = &self.store_cipher {
            key.decrypt_value(event).map_err(|e| CryptoStoreError::Backend(Box::new(e)))
        } else {
            Ok(serde_json::from_slice(event)?)
        }
    }

    async fn reset_backup_state(&self) -> Result<()> {
        let redis_key = format!("{}inbound_group_sessions", self.key_prefix);
        let mut connection = self.client.get_async_connection().await.unwrap(); // TODO: unwrap

        // Read out all the sessions, set them as not backed up
        let sessions: Vec<(String, String)> = connection.hgetall(&redis_key).await.unwrap();
        let pickles: Vec<(String, PickledInboundGroupSession)> = sessions
            .into_iter()
            .map(|(k, s)| {
                let mut pickle: PickledInboundGroupSession = serde_json::from_str(&s).unwrap();
                pickle.backed_up = false;
                (k, pickle)
            })
            .collect();

        // Write them back out in a transaction
        let mut pipeline = self.client.create_pipe();

        for (k, pickle) in pickles {
            pipeline.hset(&redis_key, &k, serde_json::to_string(&pickle).unwrap());
            // TODO: unwrap
        }

        pipeline.query_async(&mut connection).await.unwrap();

        Ok(())
    }

    //    fn upgrade(&self) -> Result<()> {
    //        let version = self
    //            .inner
    //            .get("store_version")?
    //            .map(|v| {
    //                let (version_bytes, _) =
    // v.split_at(std::mem::size_of::<u8>());
    // u8::from_be_bytes(version_bytes.try_into().unwrap_or_default())
    //            })
    //            .unwrap_or_default();
    //
    //        if version != DATABASE_VERSION {
    //            debug!(version, new_version = DATABASE_VERSION, "Upgrading the
    // Redis crypto store");        }
    //
    //        if version == 0 {
    //            // We changed the schema but migrating this isn't important since
    // we            // rotate the group sessions relatively often anyways so we
    // just            // clear the tree.
    //            self.outbound_group_sessions.clear()?;
    //        }
    //
    //        if version <= 1 {
    //            #[derive(Serialize, Deserialize)]
    //            pub struct OldReadOnlyDevice {
    //                user_id: UserId,
    //                device_id: DeviceIdBox,
    //                algorithms: Vec<EventEncryptionAlgorithm>,
    //                keys: BTreeMap<DeviceKeyId, String>,
    //                signatures: BTreeMap<UserId, BTreeMap<DeviceKeyId, String>>,
    //                display_name: Option<String>,
    //                deleted: bool,
    //                trust_state: LocalTrust,
    //            }
    //
    //            #[allow(clippy::from_over_into)]
    //            impl Into<ReadOnlyDevice> for OldReadOnlyDevice {
    //                fn into(self) -> ReadOnlyDevice {
    //                    let mut device_keys = DeviceKeys::new(
    //                        self.user_id,
    //                        self.device_id,
    //                        self.algorithms,
    //                        self.keys,
    //                        self.signatures,
    //                    );
    //                    device_keys.unsigned.device_display_name =
    // self.display_name;
    //
    //                    ReadOnlyDevice::new(device_keys, self.trust_state)
    //                }
    //            }
    //
    //            let devices: Vec<ReadOnlyDevice> = self
    //                .devices
    //                .iter()
    //                .map(|d|
    // serde_json::from_slice(&d?.1).map_err(CryptoStoreError::Serialization))
    //                .map(|d| {
    //                    let d: OldReadOnlyDevice = d?;
    //                    Ok(d.into())
    //                })
    //                .collect::<Result<Vec<ReadOnlyDevice>, CryptoStoreError>>()?;
    //
    //            self.devices.transaction(move |tree| {
    //                for device in &devices {
    //                    let key = device.encode();
    //                    let device =
    //
    // serde_json::to_vec(device).map_err(ConflictableTransactionError::Abort)?;
    //                    tree.insert(key, device)?;
    //                }
    //
    //                Ok(())
    //            })?;
    //        }
    //
    //        if version <= 2 {
    //            // We're treating our own device now differently, we're checking
    // if            // the keys match to what we have locally, remove the
    // unchecked            // device and mark our own user as dirty.
    //            if let Some(pickle) = self.account.get("account".encode())? {
    //                let pickle = serde_json::from_slice(&pickle)?;
    //                let account = ReadOnlyAccount::from_pickle(pickle,
    // self.get_pickle_mode())?;
    //
    //                self.devices
    //                    .remove((account.user_id().as_str(),
    // account.device_id.as_str()).encode())?;
    // self.tracked_users.insert(account.user_id().as_str(), &[true as u8])?;
    //            }
    //        }
    //
    //        self.inner.insert("store_version",
    // DATABASE_VERSION.to_be_bytes().as_ref())?;        self.inner.flush()?;
    //
    //        Ok(())
    //    }
    //
    //    fn open_helper(db: Db, path: Option<PathBuf>, passphrase: Option<&str>) ->
    // Result<Self> {        let account = db.open_tree("account")?;
    //        let private_identity = db.open_tree("private_identity")?;
    //
    //        let sessions = db.open_tree("session")?;
    //        let inbound_group_sessions = db.open_tree("inbound_group_sessions")?;
    //
    //        let outbound_group_sessions =
    // db.open_tree("outbound_group_sessions")?;
    //
    //        let tracked_users = db.open_tree("tracked_users")?;
    //        let olm_hashes = db.open_tree("olm_hashes")?;
    //
    //        let devices = db.open_tree("devices")?;
    //        let identities = db.open_tree("identities")?;
    //
    //        let outgoing_secret_requests =
    // db.open_tree("outgoing_secret_requests")?;        let
    // unsent_secret_requests = db.open_tree("unsent_secret_requests")?;
    //        let secret_requests_by_info =
    // db.open_tree("secret_requests_by_info")?;
    //
    //        let session_cache = SessionStore::new();
    //
    //        let pickle_key = if let Some(passphrase) = passphrase {
    //            Self::get_or_create_pickle_key(passphrase, &db)?
    //        } else {
    //            PickleKey::try_from(DEFAULT_PICKLE.as_bytes().to_vec())
    //                .expect("Can't create default pickle key")
    //        };
    //
    //        let database = Self {
    //            account_info: RwLock::new(None).into(),
    //            path,
    //            inner: db,
    //            pickle_key: pickle_key.into(),
    //            account,
    //            private_identity,
    //            sessions,
    //            session_cache,
    //            tracked_users_cache: DashSet::new().into(),
    //            users_for_key_query_cache: DashSet::new().into(),
    //            inbound_group_sessions,
    //            outbound_group_sessions,
    //            outgoing_secret_requests,
    //            unsent_secret_requests,
    //            secret_requests_by_info,
    //            devices,
    //            tracked_users,
    //            olm_hashes,
    //            identities,
    //        };
    //
    //        database.upgrade()?;
    //
    //        Ok(database)
    //    }

    async fn get_or_create_store_cipher<Conn>(
        passphrase: &str,
        key_prefix: &str,
        connection: &mut Conn,
    ) -> Result<StoreCipher>
    where
        Conn: RedisConnectionShim,
    {
        // TODO: unwraps
        let key_id = format!("{}{}", key_prefix, "store_cipher");
        let key_db_entry: Option<String> = connection.get(&key_id).await.unwrap();
        let key = if let Some(key_db_entry) = key_db_entry {
            let key_json: Vec<u8> = serde_json::from_str(&key_db_entry).unwrap();
            StoreCipher::import(passphrase, &key_json)
                .map_err(|_| CryptoStoreError::UnpicklingError)?
        } else {
            let key = StoreCipher::new().map_err(|e| CryptoStoreError::Backend(Box::new(e)))?;
            let encrypted =
                key.export(passphrase).map_err(|e| CryptoStoreError::Backend(Box::new(e)))?;
            let _: () = connection.set(&key_id, encrypted).await.unwrap();
            key
        };

        Ok(key)
    }

    async fn load_tracked_users(&self) -> Result<()> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        // TODO: unwrap
        let tracked_users: HashMap<String, Vec<u8>> =
            connection.hgetall(&format!("{}tracked_users", self.key_prefix)).await.unwrap();

        for (_, user) in tracked_users {
            let user: TrackedUser = self.deserialize_value(&user)?;

            self.tracked_users_cache.insert(user.user_id.to_owned());

            if user.dirty {
                self.users_for_key_query_cache.insert(user.user_id);
            }
        }

        Ok(())
    }

    async fn load_outbound_group_session(
        &self,
        room_id: &RoomId,
    ) -> Result<Option<OutboundGroupSession>> {
        let account_info = self.get_account_info().ok_or(CryptoStoreError::AccountUnset)?;

        let mut connection = self.client.get_async_connection().await.unwrap();
        // TODO: unwrap

        let redis_key = format!("{}outbound_session_changes", self.key_prefix);
        let session: Option<String> = connection.hget(&redis_key, room_id.as_str()).await.unwrap();

        Ok(session
            .map(|s: String| serde_json::from_str(&s).map_err(CryptoStoreError::Serialization))
            .transpose()?
            .map(|p| {
                OutboundGroupSession::from_pickle(
                    account_info.device_id,
                    account_info.identity_keys,
                    p,
                )
                .unwrap()
            }))
    }

    async fn save_changes(&self, changes: Changes) -> Result<()> {
        let account_pickle = if let Some(account) = changes.account {
            let account_info = AccountInfo {
                user_id: account.user_id.clone(),
                device_id: account.device_id.clone(),
                identity_keys: account.identity_keys.clone(),
            };

            *self.account_info.write().unwrap() = Some(account_info);
            Some(account.pickle().await)
        } else {
            None
        };

        let private_identity_pickle =
            if let Some(i) = changes.private_identity { Some(i.pickle().await?) } else { None };

        let recovery_key_pickle = changes.recovery_key;

        let device_changes = changes.devices;
        let mut session_changes: HashMap<String, Vec<PickledSession>> = HashMap::new();

        for session in changes.sessions {
            let pickle = session.pickle().await;
            let sender_key = session.sender_key().to_base64();
            session_changes.entry(sender_key).or_default().push(pickle);

            self.session_cache.add(session).await;
        }

        let mut inbound_session_changes = HashMap::new();

        for session in changes.inbound_group_sessions {
            let room_id = session.room_id();
            let sender_key = session.sender_key();
            let session_id = session.session_id();
            let key = format!("{}|{}|{}", room_id.as_str(), sender_key, session_id);
            let pickle = session.pickle().await;

            inbound_session_changes.insert(key, pickle);
        }

        let mut outbound_session_changes = HashMap::new();

        for session in changes.outbound_group_sessions {
            let room_id = session.room_id().to_owned();
            let pickle = session.pickle().await;
            outbound_session_changes.insert(room_id.clone(), pickle);
        }

        let identity_changes = changes.identities;
        let olm_hashes = changes.message_hashes;
        let key_requests = changes.key_requests;
        let backup_version = changes.backup_version;

        let mut connection = self.client.get_async_connection().await.unwrap();

        // Wrap in a Redis transaction
        let mut pipeline = self.client.create_pipe();

        if let Some(a) = &account_pickle {
            pipeline.set_vec(
                &format!("{}account", self.key_prefix),
                serde_json::to_vec(a).unwrap(), // TODO unwrap
            );
        }

        if let Some(i) = &private_identity_pickle {
            let redis_key = format!("{}private_identity", self.key_prefix);
            pipeline.set(&redis_key, serde_json::to_string(&i).unwrap());
        }

        for (key, sessions) in &session_changes {
            let redis_key = format!("{}sessions|{}", self.key_prefix, key);
            pipeline.set(&redis_key, serde_json::to_string(sessions).unwrap());
        }

        let redis_key = format!("{}inbound_group_sessions", self.key_prefix);
        for (key, inbound_group_sessions) in &inbound_session_changes {
            pipeline.hset(&redis_key, key, serde_json::to_string(inbound_group_sessions).unwrap());
            // TODO: unwrap
        }

        let redis_key = format!("{}outbound_session_changes", self.key_prefix);
        for (key, outbound_group_sessions) in &outbound_session_changes {
            pipeline.hset(
                &redis_key,
                key.as_str(),
                serde_json::to_string(outbound_group_sessions).unwrap(),
            );
            // TODO: unwrap
        }

        let redis_key = format!("{}olm_hashes", self.key_prefix);
        for hash in &olm_hashes {
            pipeline.sadd(&redis_key, serde_json::to_string(hash).unwrap());
            // TODO unwrap
        }

        let unsent_secret_requests_key = format!("{}unsent_secret_requests", self.key_prefix);

        for key_request in &key_requests {
            let key_request_id = key_request.request_id.redis_key();

            let secret_requests_by_info_key = format!(
                "{}secret_requests_by_info|{}",
                self.key_prefix,
                key_request.info.redis_key()
            );
            pipeline.set(&secret_requests_by_info_key, key_request.request_id.redis_key());

            let outgoing_secret_requests_key =
                format!("{}outgoing_secret_requests|{}", self.key_prefix, key_request_id);
            if key_request.sent_out {
                pipeline.hdel(&unsent_secret_requests_key, &key_request_id);
                pipeline.set(
                    &outgoing_secret_requests_key,
                    serde_json::to_string(&key_request).unwrap(),
                );
                // TODO: unwraps
            } else {
                pipeline.del(&outgoing_secret_requests_key);
                pipeline.hset(
                    &unsent_secret_requests_key,
                    &key_request_id,
                    serde_json::to_string(&key_request).unwrap(),
                );
                // TODO: unwraps
            }
        }

        for device in device_changes.new.iter().chain(&device_changes.changed) {
            let redis_key = format!("{}devices|{}", self.key_prefix, device.user_id());

            pipeline.hset(
                &redis_key,
                device.device_id().as_str(),
                serde_json::to_string(device).unwrap(),
            );
            // TODO: unwrap
        }

        for device in device_changes.deleted {
            let redis_key = format!("{}devices|{}", self.key_prefix, device.user_id());
            pipeline.hdel(&redis_key, device.device_id().as_str());
        }

        for identity in identity_changes.changed.iter().chain(&identity_changes.new) {
            let redis_key = format!("{}identities|{}", self.key_prefix, identity.user_id());

            pipeline.set(&redis_key, serde_json::to_string(identity).unwrap());
            // TODO: unwrap
        }

        if let Some(r) = &recovery_key_pickle {
            let redis_key = format!("{}recovery_key_v1", self.key_prefix);
            pipeline.set_vec(&redis_key, self.serialize_value(r).unwrap());
        }

        if let Some(r) = &backup_version {
            let redis_key = format!("{}backup_version_v1", self.key_prefix);
            pipeline.set_vec(&redis_key, self.serialize_value(r).unwrap());
        }

        pipeline.query_async(&mut connection).await.unwrap();
        // TODO: unwrap

        Ok(())
    }

    async fn get_outgoing_key_request_helper(
        &self,
        request_id: &str,
    ) -> Result<Option<GossipRequest>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let redis_key = format!("{}outgoing_secret_requests|{}", self.key_prefix, request_id);
        let req_string: Option<String> = connection.get(&redis_key).await.unwrap();
        let request = req_string.map(|req_string| serde_json::from_str(&req_string).unwrap());
        // TODO: unwraps

        let request = if request.is_none() {
            let redis_key = format!("{}unsent_secret_requests", self.key_prefix);
            let req_string: Option<String> = connection.hget(&redis_key, request_id).await.unwrap();
            req_string.map(|req_string| serde_json::from_str(&req_string).unwrap())
            // TODO: unwraps
        } else {
            request
        };

        Ok(request)
    }

    /// Save a batch of tracked users.
    ///
    /// # Arguments
    ///
    /// * `tracked_users` - A list of tuples. The first element of the tuple is
    /// the user ID, the second element is if the user should be considered to
    /// be dirty.
    pub async fn save_tracked_users(
        &self,
        tracked_users: &[(&UserId, bool)],
    ) -> Result<(), CryptoStoreError> {
        let mut connection = self.client.get_async_connection().await.unwrap();

        let users: Vec<TrackedUser> = tracked_users
            .iter()
            .map(|(u, d)| TrackedUser { user_id: (*u).into(), dirty: *d })
            .collect();

        // TODO: transaction?
        // TODO: unwrap

        for user in users {
            let _: () = connection
                .hset(
                    &format!("{}tracked_users", self.key_prefix),
                    user.user_id.as_str(),
                    self.serialize_value(&user).unwrap(),
                )
                .await
                .unwrap(); // TODO: unwrap
        }

        Ok(())
    }
}

#[async_trait]
impl<C> CryptoStore for RedisStore<C>
where
    C: RedisClientShim,
{
    async fn load_account(&self) -> Result<Option<ReadOnlyAccount>> {
        // TODO: many unwraps
        let mut connection = self.client.get_async_connection().await.unwrap();
        let acct_json: Option<String> =
            connection.get(&format!("{}account", self.key_prefix)).await.unwrap();

        if let Some(pickle) = acct_json {
            let pickle = serde_json::from_str(&pickle)?;
            self.load_tracked_users().await?;

            let account = ReadOnlyAccount::from_pickle(pickle)?;

            let account_info = AccountInfo {
                user_id: account.user_id.clone(),
                device_id: account.device_id.clone(),
                identity_keys: account.identity_keys.clone(),
            };

            *self.account_info.write().unwrap() = Some(account_info);

            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    async fn save_account(&self, account: ReadOnlyAccount) -> Result<()> {
        self.save_changes(Changes { account: Some(account), ..Default::default() }).await
    }

    async fn load_identity(&self) -> Result<Option<PrivateCrossSigningIdentity>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let key_prefix: String = format!("{}private_identity", self.key_prefix);
        let i_string: Option<String> = connection.get(&key_prefix).await.unwrap();
        // TODO: unwrap
        if let Some(i) = i_string {
            let pickle = serde_json::from_str(&i).unwrap();
            Ok(Some(
                PrivateCrossSigningIdentity::from_pickle(pickle)
                    .await
                    .map_err(|_| CryptoStoreError::UnpicklingError)?,
            ))
        } else {
            Ok(None)
        }
    }

    async fn save_changes(&self, changes: Changes) -> Result<()> {
        self.save_changes(changes).await
    }

    async fn get_sessions(&self, sender_key: &str) -> Result<Option<Arc<Mutex<Vec<Session>>>>> {
        let account_info = self.get_account_info().ok_or(CryptoStoreError::AccountUnset)?;

        if self.session_cache.get(sender_key).is_none() {
            let mut connection = self.client.get_async_connection().await.unwrap();

            let key = format!("{}sessions|{}", self.key_prefix, sender_key);
            let sessions_list_as_string: String =
                connection.get(&key).await.unwrap().expect("sessions list does not exist"); // TODO: unwrap
            let sessions_list: Vec<PickledSession> =
                serde_json::from_str(&sessions_list_as_string).unwrap();

            let sessions: Vec<Session> = sessions_list
                .into_iter()
                .map(|p| {
                    Session::from_pickle(
                        account_info.user_id.clone(),
                        account_info.device_id.clone(),
                        account_info.identity_keys.clone(),
                        p,
                    )
                })
                .collect();

            self.session_cache.set_for_sender(sender_key, sessions);
        }

        Ok(self.session_cache.get(sender_key))
    }

    async fn get_inbound_group_session(
        &self,
        room_id: &RoomId,
        sender_key: &str,
        session_id: &str,
    ) -> Result<Option<InboundGroupSession>> {
        // TODO: unwraps
        let key = format!("{}|{}|{}", room_id.as_str(), sender_key, session_id);
        let redis_key = format!("{}inbound_group_sessions", self.key_prefix);
        let mut connection = self.client.get_async_connection().await.unwrap();
        let pickle_str: String = connection.hget(&redis_key, &key).await.unwrap().expect(
            "Unable to find inbound group session for supplied room_id, sender_key and session_id",
        );
        let pickle = serde_json::from_str(&pickle_str).unwrap();
        // TODO: unwraps

        // TODO: could this really be None?  Might be a hangover from copying SLED
        if let Some(pickle) = pickle {
            Ok(Some(InboundGroupSession::from_pickle(pickle)?))
        } else {
            Ok(None)
        }
    }

    async fn get_inbound_group_sessions(&self) -> Result<Vec<InboundGroupSession>> {
        let redis_key = format!("{}inbound_group_sessions", self.key_prefix);
        // TODO: unwraps
        let mut connection = self.client.get_async_connection().await.unwrap();
        let igss: Vec<String> = connection.hvals(&redis_key).await.unwrap();

        let pickles: Result<Vec<PickledInboundGroupSession>> = igss
            .iter()
            .map(|p| serde_json::from_str(p).map_err(CryptoStoreError::Serialization))
            .collect();

        Ok(pickles?.into_iter().filter_map(|p| InboundGroupSession::from_pickle(p).ok()).collect())
    }

    async fn inbound_group_session_counts(&self) -> Result<RoomKeyCounts> {
        let redis_key = format!("{}inbound_group_sessions", self.key_prefix);
        // TODO: unwraps
        let mut connection = self.client.get_async_connection().await.unwrap();
        let igss: Vec<String> = connection.hvals(&redis_key).await.unwrap();

        let pickles: Result<Vec<PickledInboundGroupSession>> = igss
            .iter()
            .map(|p| serde_json::from_str(p).map_err(CryptoStoreError::Serialization))
            .collect();

        // TODO: unwraps if JSON didn't parse
        let pickles = pickles.unwrap();

        let total = pickles.len();
        let backed_up = pickles.into_iter().filter(|p| p.backed_up).count();

        Ok(RoomKeyCounts { total, backed_up })
    }

    async fn inbound_group_sessions_for_backup(
        &self,
        limit: usize,
    ) -> Result<Vec<InboundGroupSession>> {
        let redis_key = format!("{}inbound_group_sessions", self.key_prefix);
        // TODO: unwraps
        let mut connection = self.client.get_async_connection().await.unwrap();
        let igss: Vec<String> = connection.hvals(&redis_key).await.unwrap();

        let pickles = igss
            .iter()
            .map(|p| serde_json::from_str(p).map_err(CryptoStoreError::Serialization))
            .filter_map(|p: Result<PickledInboundGroupSession, CryptoStoreError>| match p {
                Ok(p) => {
                    if !p.backed_up {
                        Some(InboundGroupSession::from_pickle(p).map_err(CryptoStoreError::from))
                    } else {
                        None
                    }
                }

                Err(p) => Some(Err(p)),
            })
            .take(limit)
            .collect::<Result<_>>()?;

        Ok(pickles)
    }

    async fn reset_backup_state(&self) -> Result<()> {
        self.reset_backup_state().await
    }

    async fn get_outbound_group_sessions(
        &self,
        room_id: &RoomId,
    ) -> Result<Option<OutboundGroupSession>> {
        self.load_outbound_group_session(room_id).await
    }

    fn is_user_tracked(&self, user_id: &UserId) -> bool {
        self.tracked_users_cache.contains(user_id)
    }

    fn has_users_for_key_query(&self) -> bool {
        !self.users_for_key_query_cache.is_empty()
    }

    fn users_for_key_query(&self) -> HashSet<OwnedUserId> {
        self.users_for_key_query_cache.iter().map(|u| u.clone()).collect()
    }

    fn tracked_users(&self) -> HashSet<OwnedUserId> {
        self.tracked_users_cache.to_owned().iter().map(|u| u.clone()).collect()
    }

    async fn update_tracked_user(&self, user: &UserId, dirty: bool) -> Result<bool> {
        let already_added = self.tracked_users_cache.insert(user.to_owned());

        if dirty {
            self.users_for_key_query_cache.insert(user.to_owned());
        } else {
            self.users_for_key_query_cache.remove(user);
        }

        self.save_tracked_users(&[(user, dirty)]).await?;

        Ok(already_added)
    }

    async fn get_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<Option<ReadOnlyDevice>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let key = format!("{}devices|{}", self.key_prefix, user_id);
        let dev: Option<String> = connection.hget(&key, device_id.as_str()).await.unwrap();
        Ok(dev.map(|d| serde_json::from_str(&d).unwrap()))
    }

    async fn get_user_devices(
        &self,
        user_id: &UserId,
    ) -> Result<HashMap<OwnedDeviceId, ReadOnlyDevice>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let user_device: HashMap<String, String> =
            connection.hgetall(&format!("{}devices|{}", self.key_prefix, user_id)).await.unwrap();

        Ok(user_device
            .into_iter()
            .map(|(device_id, device_str)| {
                (device_id.into(), serde_json::from_str(&device_str).unwrap())
            })
            .collect())

        // TODO: unwrap
    }

    async fn get_user_identity(&self, user_id: &UserId) -> Result<Option<ReadOnlyUserIdentities>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let redis_key = format!("{}identities|{}", self.key_prefix, user_id);
        let identity_string: String =
            connection.get(&redis_key).await.unwrap().expect("identities list does not exist");
        let identity: Option<ReadOnlyUserIdentities> =
            serde_json::from_str(&identity_string).unwrap();
        Ok(identity)
        // TODO: unwrap
    }

    async fn is_message_known(
        &self,
        message_hash: &matrix_sdk_crypto::olm::OlmMessageHash,
    ) -> Result<bool> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let redis_key = format!("{}olm_hashes", self.key_prefix);
        Ok(connection
            .sismember(&redis_key, &serde_json::to_string(message_hash).unwrap())
            .await
            .unwrap())
        // TODO: unwrap
    }

    async fn get_outgoing_secret_requests(
        &self,
        request_id: &TransactionId,
    ) -> Result<Option<GossipRequest>> {
        self.get_outgoing_key_request_helper(&request_id.redis_key()).await
    }

    async fn get_secret_request_by_info(
        &self,
        key_info: &SecretInfo,
    ) -> Result<Option<GossipRequest>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let redis_key =
            format!("{}secret_requests_by_info|{}", self.key_prefix, key_info.redis_key());
        let id: Option<String> = connection.get(&redis_key).await.unwrap();

        if let Some(id) = id {
            self.get_outgoing_key_request_helper(&id).await
        } else {
            Ok(None)
        }
    }

    async fn get_unsent_secret_requests(&self) -> Result<Vec<GossipRequest>> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let redis_key = format!("{}unsent_secret_requests", self.key_prefix);
        let req_map: HashMap<String, String> = connection.hgetall(&redis_key).await.unwrap();
        Ok(req_map.iter().map(|(_, req)| serde_json::from_str(&req).unwrap()).collect())
    }

    async fn delete_outgoing_secret_requests(&self, request_id: &TransactionId) -> Result<()> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let okr_req_id_key =
            format!("{}outgoing_secret_requests|{}", self.key_prefix, request_id.redis_key());
        let sent_request: Option<String> = connection.get(&okr_req_id_key).await.unwrap();

        // Wrap the deletes in a Redis transaction
        // TODO: race: if someone updates sent_request before we delete it, we
        // could be deleting the old stuff, when others are using a newer version,
        // so we would be in an inconsistent state where the sent_request is deleted,
        // but the things it refers to still exist.
        let mut pipeline = self.client.create_pipe();
        if let Some(sent_request) = sent_request {
            pipeline.del(&okr_req_id_key);
            let usr_key = format!("{}unsent_secret_requests", self.key_prefix);
            pipeline.hdel(&usr_key, &request_id.redis_key());
            let sent_request: GossipRequest = serde_json::from_str(&sent_request).unwrap();
            let srbi_info_key = format!(
                "{}secret_requests_by_info|{}",
                self.key_prefix,
                sent_request.info.redis_key()
            );
            pipeline.del(&srbi_info_key);
        }
        pipeline.query_async(&mut connection).await.unwrap();
        // TODO: unwrap

        Ok(())
    }

    async fn load_backup_keys(&self) -> Result<BackupKeys> {
        let mut connection = self.client.get_async_connection().await.unwrap();
        let redis_key = format!("{}backup_version_v1", self.key_prefix);
        // TODO: unwrap
        let version_v: Option<Vec<u8>> = connection.get(&redis_key).await.unwrap();
        let version = version_v.map(|v| self.deserialize_value(&v).unwrap());

        let redis_key = format!("{}recovery_key_v1", self.key_prefix);
        // TODO: unwrap
        let recovery_key_str: Option<Vec<u8>> = connection.get(&redis_key).await.unwrap();
        let recovery_key: Option<RecoveryKey> =
            recovery_key_str.map(|s| self.deserialize_value(&s).unwrap());

        Ok(BackupKeys { backup_version: version, recovery_key })
    }
}

#[cfg(test)]
mod test_fake_redis {
    use std::{collections::HashMap, sync::Arc};

    use matrix_sdk_crypto::cryptostore_integration_tests;
    use once_cell::sync::Lazy;
    use redis::{ConnectionAddr, ConnectionInfo, RedisConnectionInfo};
    use tokio::sync::Mutex;

    use super::RedisStore;
    use crate::fake_redis::FakeRedisClient;

    static REDIS_CLIENT: Lazy<FakeRedisClient> = Lazy::new(|| FakeRedisClient::new());

    async fn get_store(name: String, passphrase: Option<&str>) -> RedisStore<FakeRedisClient> {
        // TODO: consider using name to choose which fake to return from some map?
        let key_prefix = format!("matrix-sdk-crypto|test|{}|", name);
        RedisStore::open(REDIS_CLIENT.clone(), passphrase, key_prefix)
            .await
            .expect("Can't create a Redis store")
    }

    cryptostore_integration_tests! { integration }
}

// To run tests against a real Redis, use:
// ```sh
// cargo test redis --features=real-redis-tests
// ```
#[cfg(feature = "real-redis-tests")]
#[cfg(test)]
mod test_real_redis {
    use matrix_sdk_crypto::cryptostore_integration_tests;
    use once_cell::sync::Lazy;
    use redis::{AsyncCommands, Client, Commands};

    use super::RedisStore;
    use crate::real_redis::RealRedisClient;

    static REDIS_URL: &str = "redis://127.0.0.1/";

    // We pretend to use this as our shared client, so that
    // we clear Redis the first time we access it, but actually
    // we clone it each time we use it, so they are independent.
    static REDIS_CLIENT: Lazy<Client> = Lazy::new(|| {
        let client = Client::open(REDIS_URL).unwrap();
        let mut connection = client.get_connection().unwrap();
        let keys: Vec<String> = connection.keys("matrix-sdk-crypto|test|*").unwrap();
        for k in keys {
            let _: () = connection.del(k).unwrap();
        }
        client
    });

    async fn get_store(name: String, passphrase: Option<&str>) -> RedisStore<RealRedisClient> {
        let key_prefix = format!("matrix-sdk-crypto|test|{}|", name);
        let redis_client = RealRedisClient::from(REDIS_CLIENT.clone());
        let store = RedisStore::open(redis_client, passphrase, key_prefix)
            .await
            .expect("Can't create a Redis store");

        store
    }

    cryptostore_integration_tests! { integration }
}
