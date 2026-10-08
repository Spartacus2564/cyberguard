import Redis from 'ioredis';
import { config } from '../config';
import logger from '../utils/logger';

const globalForRedis = globalThis as unknown as { redis: Redis };

function createRedisClient(): Redis {
  const client = new Redis(config.redisUrl, {
    maxRetriesPerRequest: 3,
    retryStrategy(times: number) {
      if (times > 10) {
        logger.error('Redis: max retries exceeded, giving up');
        return null;
      }
      const delay = Math.min(times * 200, 5000);
      logger.warn(`Redis: reconnecting in ${delay}ms (attempt ${times})`);
      return delay;
    },
    lazyConnect: false,
    enableReadyCheck: true,
    connectTimeout: 10000,
  });

  client.on('error', (err) => {
    logger.error('Redis connection error:', { error: err.message });
  });

  client.on('reconnecting', (delay: number) => {
    logger.warn(`Redis: reconnecting in ${delay}ms`);
  });

  client.on('ready', () => {
    logger.info('Redis: connected and ready');
  });

  return client;
}

const redis = globalForRedis.redis || createRedisClient();
globalForRedis.redis = redis;

export default redis;
