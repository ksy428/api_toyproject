package seyoung.toyproject.global.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import seyoung.toyproject.domain.member.repository.MemberRepository;
import seyoung.toyproject.global.redis.service.RedisService;

import java.io.IOException;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Transactional
@Service
@RequiredArgsConstructor
@Setter(value = AccessLevel.PRIVATE)
public class JwtServiceImpl implements JwtService{

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.access.expiration}")
    private long accessTokenValidityInSeconds;
    @Value("${jwt.refresh.expiration}")
    private long refreshTokenValidityInSeconds;
    @Value("${jwt.access.header}")
    private String accessHeader;
    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String USERID_CLAIM = "userId";
    private static final String BEARER = "Bearer ";

    private final MemberRepository memberRepository;
    private final ObjectMapper objectMapper;

    private final RedisService redisService;

    @Override
    public String createAccessToken(String userId) {

        String accessToken = JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenValidityInSeconds * 1000))
                .withClaim(USERID_CLAIM, userId)
                .sign(Algorithm.HMAC512(secret));
        Duration duration = Duration.ofMillis(1000 * accessTokenValidityInSeconds);
        redisService.setAccessToken(userId, accessToken, duration);
        return accessToken;
    }

    @Override
    public String createRefreshToken() {
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenValidityInSeconds * 1000))
                .sign(Algorithm.HMAC512(secret));
    }

    @Override
    public void updateRefreshToken(String userId, String refreshToken) {
        memberRepository.findByUserId(userId)
                .ifPresentOrElse(
                        member -> member.updateRefreshToken(refreshToken),
                        () -> new Exception("회원이 없습니다")
                );
    }

    @Override
    public void destroyRefreshToken(String userId) {
        memberRepository.findByUserId(userId)
                .ifPresentOrElse(
                        member -> member.destroyRefreshToken(),
                        () -> new Exception("회원이 없습니다")
                );
    }
    @Override
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        response.setStatus(HttpServletResponse.SC_OK);
        setAccessTokenHeader(response, accessToken);
        setRefreshTokenHeader(response, refreshToken);
    }

    @Override
    public void sendAccessToken(HttpServletResponse response, String accessToken){
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        setAccessTokenHeader(response, accessToken);
    }

    @Override
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader)).filter(
                accessToken -> accessToken.startsWith(BEARER)
        ).map(accessToken -> accessToken.replace(BEARER, ""));
    }

    @Override
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader)).filter(
                refreshToken -> refreshToken.startsWith(BEARER)
        ).map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    @Override
    public Optional<String> extractUserId(String accessToken) {
        try {
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secret)).build().verify(accessToken).getClaim(USERID_CLAIM).asString());
        }catch (Exception e){
            log.error(e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    @Override
    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    }

    @Override
    public boolean isValid(String token){
        try {
            JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
            return true;
        }catch (Exception e){
            log.error("유효하지 않은 Token입니다", e.getMessage());
            return false;
        }
    }
}
