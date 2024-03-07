package seyoung.toyproject.global.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;
import seyoung.toyproject.domain.member.Member;
import seyoung.toyproject.domain.member.repository.MemberRepository;
import seyoung.toyproject.global.jwt.service.JwtService;
import seyoung.toyproject.global.redis.service.RedisService;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final MemberRepository memberRepository;
    private final RedisService redisService;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    private final String NO_CHECK_URL = "/login";
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().equals(NO_CHECK_URL)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = jwtService.extractAccessToken(request).filter(jwtService::isValid).orElse(null);
        String userId = jwtService.extractUserId(accessToken).orElse(null);
        Boolean isAccessTokenInRedis = false;
        if(accessToken != null){
            if(accessToken.equals(redisService.getAccessTokenByUserId(userId))){
                isAccessTokenInRedis = true;
            }
        }
        // accessToken 유효
        if(isAccessTokenInRedis){
            memberRepository.findByUserId(userId).ifPresent(
                    this::saveAuthentication
            );
        }
        else{ // accessToken 유효하지않음. refreshToken 체크
            String refreshToken = jwtService.extractRefreshToken(request).filter(jwtService::isValid).orElse(null);
            //유효한 refreshToken 이면 accessToken 재발급. 403응답
            if(refreshToken != null){
                checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            }
            //accessToken, refreshToken 둘다 유효하지않음. 401응답
            else{
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
    }
    //DB에 저장한 refreshToken 이 맞는지 유효성 체크. 맞으면 accessToken 발급
    private void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        memberRepository.findByRefreshToken(refreshToken).ifPresent(
                member -> jwtService.sendAccessToken(response, jwtService.createAccessToken(member.getUserId()))
        );
    }
    //인증생성
    private void saveAuthentication(Member member) {
        UserDetails user = User.builder()
                .username(member.getUserId())
                .password(member.getPassword())
                .roles(member.getRole().name())
                .build();

        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null,authoritiesMapper.mapAuthorities(user.getAuthorities()));
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }
}
