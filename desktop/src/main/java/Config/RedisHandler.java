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

    public int checkData(String login, String password)
    {
        try {
            if (redisHandler.hget("account", login) != null) {
                if (redisHandler.hget("account", login).equals(password))
                {
                    createRedisRecord(login);
                    return 0;
                }
                else
                {
                    return 1;
                }
            }
            return 1;
        }
        catch (JedisConnectionException e)
        {
            return -1;
        }
    }

    public void deleteRedisRecord(String login)
    {
        redisHandler.hdel("DesktopLoginLogged", login);
    }

    private void createRedisRecord(String login)
    {
        SimpleDateFormat formatter= new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = new Date(System.currentTimeMillis());
        redisHandler.hset("DesktopLoginHistory", login, formatter.format(date));
        redisHandler.hset("DesktopLoginLogged", login, formatter.format(date));
    }

    public Jedis getRedisHandler() {
        return redisHandler;
    }

    public void setRedisHandler(Jedis redisHandler) {
        this.redisHandler = redisHandler;
    }
}
