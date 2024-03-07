package seyoung.toyproject.global.redis.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
public class RedisServiceImpl implements RedisService {

    private final StringRedisTemplate redisTemplate;

    public static final String REDIS_PREFIX_KEY = "";


    @Override
    public void setAccessToken(String key, String accessToken) {
        ValueOperations<String, String> values = redisTemplate.opsForValue();
        values.set(REDIS_PREFIX_KEY + key, accessToken);
    }

    @Override
    public void setAccessToken(String key, String accessToken, Duration duration) {
        ValueOperations<String, String> values = redisTemplate.opsForValue();
        values.set(REDIS_PREFIX_KEY + key, accessToken, duration);
    }

    @Override
    public String getAccessTokenByUserId(String userId) {
        ValueOperations<String, String> values = redisTemplate.opsForValue();
        return values.get(userId);
    }

    @Override
    public void removeAccessToken(String key) {
        redisTemplate.delete(REDIS_PREFIX_KEY + key);
    }
}
