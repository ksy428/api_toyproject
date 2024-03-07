package seyoung.toyproject.global.redis.service;

import java.time.Duration;

public interface RedisService {

    void setAccessToken(String key, String accessToken);

    void setAccessToken(String key, String accessToken, Duration duration);

    String getAccessTokenByUserId(String userId);

    void removeAccessToken(String key);
}
