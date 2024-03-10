package seyoung.toyproject.global.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.transaction.annotation.Transactional;
import seyoung.toyproject.domain.member.repository.MemberRepository;
import seyoung.toyproject.global.jwt.service.JwtService;
import seyoung.toyproject.global.redis.service.RedisService;

import java.io.IOException;


@Slf4j
@RequiredArgsConstructor
@Transactional
public class CustomLogoutHandler implements LogoutHandler {

    private final JwtService jwtService;
    private final RedisService redisService;
    private final MemberRepository memberRepository;
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        log.info("::::::::CustomLogoutHandler::::::::");
        String accessToken = jwtService.extractAccessToken(request).filter(jwtService::isValid).orElse(null);

        if(accessToken != null) {
            String userId = jwtService.extractUserId(accessToken).orElse(null);
            redisService.removeAccessToken(userId);
            memberRepository.findByUserId(userId)
                    .ifPresentOrElse(
                            member -> member.updateRefreshToken(""),
                            () -> new Exception("회원이 없습니다")
                    );
            log.info("::::::::로그아웃 성공::::::::");
        }
        else{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
