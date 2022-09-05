use async_trait::async_trait;
use redis::{FromRedisValue, RedisFuture, RedisResult, ToRedisArgs};

pub trait RedisConnectionShim: Send {
    fn del<'a>(&'a mut self, key: &str) -> RedisFuture<'a, ()>;

    fn get<'a, RV>(&'a mut self, key: &str) -> RedisFuture<'a, Option<RV>>
    where
        RV: FromRedisValue;

    fn set<'a, V>(&'a mut self, key: &str, value: V) -> RedisFuture<'a, ()>
    where
        V: ToRedisArgs + Send + Sync + 'a;

    fn hdel<'a>(&'a mut self, key: &str, field: &str) -> RedisFuture<'a, ()>;

    fn hgetall<'a, RV>(&'a mut self, key: &str) -> RedisFuture<'a, RV>
    where
        RV: FromRedisValue;

    fn hvals<'a>(&'a mut self, key: &str) -> RedisFuture<'a, Vec<String>>;

    fn hget<'a, RV>(&'a mut self, key: &str, field: &'a str) -> RedisFuture<'a, Option<RV>>
    where
        RV: FromRedisValue + Clone;

    fn hset<'a>(&'a mut self, key: &str, field: &str, value: Vec<u8>) -> RedisFuture<'a, ()>;

    fn sadd<'a>(&'a mut self, key: &str, value: String) -> RedisFuture<'a, ()>;

    fn sismember<'a>(&'a mut self, key: &str, member: &str) -> RedisFuture<'a, bool>;
}

#[async_trait]
pub trait RedisClientShim: Clone + Send + Sync {
    type Conn: RedisConnectionShim;

    async fn get_async_connection(&self) -> RedisResult<Self::Conn>;
    fn get_connection_info(&self) -> &redis::ConnectionInfo;
    fn create_pipe(&self) -> Box<dyn RedisPipelineShim<Conn = Self::Conn>>;
}

#[async_trait]
pub trait RedisPipelineShim: Send + Sync {
    type Conn: RedisConnectionShim;

    fn set(&mut self, key: &str, value: String);
    fn set_vec(&mut self, key: &str, value: Vec<u8>);
    fn del(&mut self, key: &str);
    fn hset(&mut self, key: &str, field: &str, value: String);
    fn hdel(&mut self, key: &str, field: &str);
    fn sadd(&mut self, key: &str, value: String);

    async fn query_async(&self, connection: &mut Self::Conn) -> RedisResult<()>;
}
