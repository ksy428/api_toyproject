package seyoung.toyproject.global.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import seyoung.toyproject.global.jwt.service.JwtService;
import seyoung.toyproject.global.redis.service.RedisService;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private final JwtService jwtService;
    private final RedisService redisService;
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("::::::::CustomLogoutSuccessHandler::::::::");


    }
}
