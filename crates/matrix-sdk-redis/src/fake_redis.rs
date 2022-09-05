use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use async_trait::async_trait;
use redis::{FromRedisValue, RedisConnectionInfo, RedisFuture, RedisResult, ToRedisArgs};

use crate::redis_shim::{RedisClientShim, RedisConnectionShim, RedisPipelineShim};

#[derive(Clone)]
pub struct FakeRedisConnection {
    values: Arc<std::sync::Mutex<HashMap<String, redis::Value>>>,
}

impl RedisConnectionShim for FakeRedisConnection {
    fn del<'a>(&'a mut self, key: &str) -> RedisFuture<'a, ()> {
        self.values.lock().unwrap().remove(key);
        Box::pin(async move { Ok(()) })
    }

    fn get<'a, RV>(&'a mut self, key: &str) -> RedisFuture<'a, Option<RV>>
    where
        RV: FromRedisValue,
    {
        let ret = self.values.lock().unwrap().get(key).cloned();
        Box::pin(async move {
            match ret {
                None => Ok(None),
                Some(r) => RV::from_redis_value(&r).map(|v| Some(v)),
            }
        })
    }

    fn set<'a, V>(&'a mut self, key: &str, value: V) -> RedisFuture<'a, ()>
    where
        V: ToRedisArgs + Send + Sync + 'a,
    {
        let vs = value.to_redis_args();
        assert_eq!(vs.len(), 1);
        let v: redis::Value = redis::Value::Data(vs[0].clone());
        self.values.lock().unwrap().insert(String::from(key), v);
        Box::pin(async move { Ok(()) })
    }

    fn hgetall<'a, RV>(&'a mut self, key: &str) -> RedisFuture<'a, RV>
    where
        RV: FromRedisValue,
    {
        let ret = self
            .values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_else(|| redis::Value::Bulk(Vec::new()));
        Box::pin(async move { RV::from_redis_value(&ret) })
    }

    fn hdel<'a>(&'a mut self, key: &str, field: &str) -> RedisFuture<'a, ()> {
        let mut values = self.values.lock().unwrap();
        let entry = values
            .entry(String::from(key))
            .or_insert(to_redis_value(BTreeMap::<String, Vec<u8>>::new()));
        let mut full_map: BTreeMap<String, Vec<u8>> = BTreeMap::from_redis_value(entry)
            .expect(&format!("Tried to hdel {} as a btreemap, but it is not a btreemap!", key));
        full_map.remove(field);

        // Replace the entry at key with this modified hashmap
        *entry = to_redis_value(full_map);

        // Return a future
        Box::pin(async move { Ok(()) })
    }

    fn hget<'a, RV>(&'a mut self, key: &str, field: &str) -> RedisFuture<'a, Option<RV>>
    where
        RV: FromRedisValue + Clone,
    {
        let value = self
            .values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_else(|| redis::Value::Bulk(Vec::new()));

        let field = String::from(field);

        Box::pin(async move {
            BTreeMap::<String, RV>::from_redis_value(&value).map(|hm| hm.get(&field).cloned())
        })
    }

    fn hset<'a>(&'a mut self, key: &str, field: &str, value: Vec<u8>) -> RedisFuture<'a, ()> {
        let mut values = self.values.lock().unwrap();
        let entry = values
            .entry(String::from(key))
            .or_insert(to_redis_value(BTreeMap::<String, Vec<u8>>::new()));
        let mut full_map: BTreeMap<String, Vec<u8>> = BTreeMap::from_redis_value(entry)
            .expect(&format!("Tried to hset {} as a btreemap, but it is not a btreemap!", key));
        full_map.insert(String::from(field), value);

        // Replace the entry at key with this modified hashmap
        *entry = to_redis_value(full_map);

        // Return a future
        Box::pin(async move { Ok(()) })
    }

    fn hvals<'a>(&'a mut self, key: &str) -> RedisFuture<'a, Vec<String>> {
        let value = self
            .values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_else(|| redis::Value::Bulk(Vec::new()));

        Box::pin(async move {
            BTreeMap::<String, String>::from_redis_value(&value)
                .map(|hm| hm.values().cloned().collect())
        })
    }

    fn sadd<'a>(&'a mut self, key: &str, value: String) -> RedisFuture<'a, ()> {
        let mut values = self.values.lock().unwrap();
        let entry =
            values.entry(String::from(key)).or_insert(to_redis_value(BTreeSet::<String>::new()));
        let mut full_map: BTreeSet<String> = BTreeSet::from_redis_value(entry)
            .expect(&format!("Tried to sadd {} as a btreeset, but it is not a btreeset!", key));
        full_map.insert(value);

        // Replace the entry at key with this modified hashmap
        *entry = to_redis_value(full_map);

        // Return a future
        Box::pin(async move { Ok(()) })
    }

    fn sismember<'a>(&'a mut self, key: &str, member: &str) -> RedisFuture<'a, bool> {
        let value = self
            .values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_else(|| redis::Value::Bulk(Vec::new()));

        let member = String::from(member);

        Box::pin(async move {
            BTreeSet::<String>::from_redis_value(&value).map(|se| se.contains(&member))
        })
    }
}

fn to_redis_value<T>(obj: T) -> redis::Value
where
    T: ToRedisArgs,
{
    let bytes_vec = obj.to_redis_args();
    let bytes: Vec<redis::Value> =
        bytes_vec.iter().map(|item| redis::Value::Data(item.clone())).collect();
    redis::Value::Bulk(bytes)
}

#[derive(Clone)]
pub struct FakeRedisClient {
    connection_info: redis::ConnectionInfo,
    values: Arc<std::sync::Mutex<HashMap<String, redis::Value>>>,
}

impl FakeRedisClient {
    pub fn new() -> Self {
        Self {
            connection_info: redis::ConnectionInfo {
                addr: redis::ConnectionAddr::Tcp(String::from(""), 0),
                redis: RedisConnectionInfo { db: 0, username: None, password: None },
            },
            values: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl RedisClientShim for FakeRedisClient {
    type Conn = FakeRedisConnection;

    async fn get_async_connection(&self) -> RedisResult<Self::Conn> {
        Ok(FakeRedisConnection { values: self.values.clone() })
    }

    fn get_connection_info(&self) -> &redis::ConnectionInfo {
        &self.connection_info
    }

    fn create_pipe(&self) -> Box<dyn RedisPipelineShim<Conn = Self::Conn>> {
        Box::new(FakeRedisPipeline::new())
    }
}

enum PipelineCommand {
    Del(String),
    Hdel(String, String),
    Hset(String, String, String),
    Sadd(String, String),
    Set(String, String),
    SetVec(String, Vec<u8>),
}

struct FakeRedisPipeline {
    cmds: Vec<PipelineCommand>,
}

impl FakeRedisPipeline {
    pub fn new() -> Self {
        Self { cmds: Vec::new() }
    }
}

#[async_trait]
impl RedisPipelineShim for FakeRedisPipeline {
    type Conn = FakeRedisConnection;

    fn set(&mut self, key: &str, value: String) {
        self.cmds.push(PipelineCommand::Set(String::from(key), value));
    }

    fn set_vec(&mut self, key: &str, value: Vec<u8>) {
        self.cmds.push(PipelineCommand::SetVec(String::from(key), value));
    }

    fn del(&mut self, key: &str) {
        self.cmds.push(PipelineCommand::Del(String::from(key)));
    }

    fn hset(&mut self, key: &str, field: &str, value: String) {
        self.cmds.push(PipelineCommand::Hset(String::from(key), String::from(field), value));
    }

    fn hdel(&mut self, key: &str, field: &str) {
        self.cmds.push(PipelineCommand::Hdel(String::from(key), String::from(field)));
    }

    fn sadd(&mut self, key: &str, value: String) {
        self.cmds.push(PipelineCommand::Sadd(String::from(key), String::from(value)));
    }

    async fn query_async(&self, connection: &mut Self::Conn) -> RedisResult<()> {
        for cmd in &self.cmds {
            match cmd {
                PipelineCommand::Del(key) => connection.del(key).await?,
                PipelineCommand::Hdel(key, field) => connection.hdel(key, field).await?,
                PipelineCommand::Hset(key, field, value) => {
                    connection.hset(key, field, value.clone().into_bytes()).await?
                }
                PipelineCommand::Sadd(key, value) => {
                    connection.sadd(&key, value.to_owned()).await?
                }
                PipelineCommand::Set(key, value) => connection.set(key, value).await?,
                PipelineCommand::SetVec(key, value) => connection.set(key, value).await?,
            }
        }
        Ok(())
    }
}
