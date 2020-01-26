import redis
import hashlib


class RedisHandler:
    def __init__(self, redisConnection):
        self.redisConnection = redisConnection

    def getMessage(self):
        return self.redisConnection.pubsub(ignore_subscribe_messages=True)

