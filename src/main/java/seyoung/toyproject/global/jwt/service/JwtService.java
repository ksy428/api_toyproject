package seyoung.toyproject.global.jwt.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Optional;

public interface JwtService {

    String createAccessToken(String userId);
    String createRefreshToken();

    void updateRefreshToken(String userId, String refreshToken);

    void destroyRefreshToken(String userId);


    void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken);
    void sendAccessToken(HttpServletResponse response, String accessToken);


    String  extractAccessToken(HttpServletRequest request) throws IOException, ServletException;

    String  extractRefreshToken(HttpServletRequest request) throws IOException, ServletException;

    String  extractUserId(String accessToken);

    void setAccessTokenHeader(HttpServletResponse response, String accessToken);
    void setRefreshTokenHeader(HttpServletResponse response, String refreshToken);

    boolean isTokenValid(String token);
}
