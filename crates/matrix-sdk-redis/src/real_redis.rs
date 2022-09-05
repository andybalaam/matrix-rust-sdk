use async_trait::async_trait;
use redis::{AsyncCommands, FromRedisValue, RedisFuture, RedisResult, ToRedisArgs};

use crate::redis_shim::{RedisClientShim, RedisConnectionShim, RedisPipelineShim};

impl RedisConnectionShim for redis::aio::Connection {
    fn del<'a>(&'a mut self, key: &str) -> RedisFuture<'a, ()> {
        AsyncCommands::del(self, key.to_owned())
    }

    fn get<'a, RV>(&'a mut self, key: &str) -> RedisFuture<'a, Option<RV>>
    where
        RV: FromRedisValue,
    {
        AsyncCommands::get(self, key.to_owned())
    }

    fn set<'a, V>(&'a mut self, key: &str, value: V) -> RedisFuture<'a, ()>
    where
        V: ToRedisArgs + Send + Sync + 'a,
    {
        AsyncCommands::set::<&str, V, ()>(self, key, value);
        Box::pin(async move { Ok(()) })
    }

    fn hdel<'a>(&'a mut self, key: &str, field: &str) -> RedisFuture<'a, ()> {
        AsyncCommands::hdel(self, key.to_owned(), field.to_owned())
    }

    fn hgetall<'a, RV>(&'a mut self, key: &str) -> RedisFuture<'a, RV>
    where
        RV: FromRedisValue,
    {
        AsyncCommands::hgetall(self, key.to_owned())
    }

    fn hvals<'a>(&'a mut self, key: &str) -> RedisFuture<'a, Vec<String>> {
        AsyncCommands::hvals(self, key.to_owned())
    }

    fn hget<'a, RV>(&'a mut self, key: &str, field: &'a str) -> RedisFuture<'a, Option<RV>>
    where
        RV: FromRedisValue + Clone,
    {
        AsyncCommands::hget(self, key.to_owned(), field.to_owned())
    }

    fn hset<'a>(&'a mut self, key: &str, field: &str, value: Vec<u8>) -> RedisFuture<'a, ()> {
        AsyncCommands::hset::<_, _, _, ()>(self, key.to_owned(), field.to_owned(), value)
        // TODO: maybe more efficient to return Box::pin(async move { Ok(()) })
        //  - then we don't need to_owned()
    }

    fn sadd<'a>(&'a mut self, key: &str, value: String) -> RedisFuture<'a, ()> {
        AsyncCommands::sadd(self, key.to_owned(), value)
    }

    fn sismember<'a>(&'a mut self, key: &str, member: &str) -> RedisFuture<'a, bool> {
        AsyncCommands::sismember(self, key.to_owned(), member.to_owned())
    }
}

#[derive(Clone)]
pub struct RealRedisClient {
    client: redis::Client,
}

impl RealRedisClient {
    #[cfg(feature = "real-redis-tests")]
    #[cfg(test)]
    pub fn from(client: redis::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl RedisClientShim for RealRedisClient {
    type Conn = redis::aio::Connection;

    async fn get_async_connection(&self) -> RedisResult<Self::Conn> {
        self.client.get_async_connection().await
    }

    fn get_connection_info(&self) -> &redis::ConnectionInfo {
        self.client.get_connection_info()
    }

    fn create_pipe(&self) -> Box<dyn RedisPipelineShim<Conn = Self::Conn>> {
        Box::new(RealRedisPipeline::new())
    }
}

pub struct RealRedisPipeline {
    pipeline: redis::Pipeline,
}

impl RealRedisPipeline {
    fn new() -> Self {
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        Self { pipeline }
    }
}

#[async_trait]
impl RedisPipelineShim for RealRedisPipeline {
    type Conn = redis::aio::Connection;

    fn set(&mut self, key: &str, value: String) {
        self.pipeline.set(key, value);
    }

    fn set_vec(&mut self, key: &str, value: Vec<u8>) {
        self.pipeline.set(key, value);
    }

    fn del(&mut self, key: &str) {
        self.pipeline.del(key);
    }

    fn hset(&mut self, key: &str, field: &str, value: String) {
        self.pipeline.hset(key, field, value);
    }

    fn hdel(&mut self, key: &str, field: &str) {
        self.pipeline.hdel(key, field);
    }

    fn sadd(&mut self, key: &str, value: String) {
        self.pipeline.sadd(key, value);
    }

    async fn query_async(&self, connection: &mut Self::Conn) -> RedisResult<()> {
        self.pipeline.query_async(connection).await
    }
}
