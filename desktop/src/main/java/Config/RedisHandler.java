package Config;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.exceptions.JedisConnectionException;
import redis.clients.jedis.exceptions.JedisException;

import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class RedisHandler {
    private Jedis redisHandler;

    public RedisHandler(String url, int port)
    {
        try {
            redisHandler = new Jedis(url, port);
        }
        catch (JedisException e)
        {
            redisHandler = null;
        }
    }


    public Jedis getRedisHandler() {
        return redisHandler;
    }

    public void setRedisHandler(Jedis redisHandler) {
        this.redisHandler = redisHandler;
    }
}
