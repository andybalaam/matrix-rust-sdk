#[cfg(test)]
mod fake_redis;
mod real_redis;
#[cfg(feature = "e2e-encryption")]
mod redis_crypto_store;
mod redis_shim;

#[cfg(feature = "e2e-encryption")]
pub use redis_crypto_store::RedisStore as CryptoStore;
