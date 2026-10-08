const redis = require('ioredis');
const r = new redis(process.env.REDIS_URL || 'redis://localhost:6379');
(async () => {
  // Find the latest scan's logs
  const keys = await r.keys('scan:*:logs');
  console.log('Log keys:', keys.length);
  for (const key of keys.slice(-3)) {
    const logs = await r.lrange(key, 0, -1);
    console.log('\n=== ' + key + ' (' + logs.length + ' entries) ===');
    for (const l of logs) {
      try {
        const entry = JSON.parse(l);
        if (entry.message) console.log(' ', entry.level || 'info', entry.message.substring(0, 120));
      } catch {}
    }
  }
  await r.quit();
})();
