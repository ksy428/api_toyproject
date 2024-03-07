package seyoung.toyproject.global.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.transaction.annotation.Transactional;
import seyoung.toyproject.domain.member.Member;
import seyoung.toyproject.domain.member.Role;
import seyoung.toyproject.domain.member.repository.MemberRepository;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@Transactional
@AutoConfigureMockMvc
@Slf4j
class JwtServiceImplTest {

    @Autowired
    MemberRepository memberRepository;
    @Autowired
    MockMvc mockMvc;
    @Autowired JwtService jwtService;
    PasswordEncoder passwordEncoder =  new BCryptPasswordEncoder();
    ObjectMapper objectMapper = new ObjectMapper();

    private static String KEY_USERID = "userId";
    private static String KEY_PASSWORD = "password";
    private static String USERID = "seyoung";
    private static String PASSWORD = "123456789";
    private static String LOGIN_URL = "/login";

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String USERID_CLAIM = "userId";
    private static final String BEARER = "Bearer ";


    @Value("${jwt.access.header}")
    private String accessHeader;
    @Value("${jwt.refresh.header}")
    private String refreshHeader;
    @Value("${jwt.secret}")
    private String secret;

    @BeforeEach
    public void init(){
        memberRepository.save(Member.builder()
                .userId(USERID)
                .password(passwordEncoder.encode(PASSWORD))
                .role(Role.MEMBER)
                .build());
    }

    private Map getUserIdPasswordMap(String userId, String password){
        Map<String, String> map = new HashMap<>();
        map.put(KEY_USERID, userId);
        map.put(KEY_PASSWORD, password);
        return map;
    }

    private ResultActions perform(String url, MediaType mediaType, Map loginInfo) throws Exception {
        return mockMvc.perform(MockMvcRequestBuilders
                .post(url)
                .contentType(mediaType)
                .content(objectMapper.writeValueAsString(loginInfo)));
    }

    @Test
    public void getAccessToken() throws Exception {
        //given
        String accessToken = jwtService.createAccessToken(USERID);

        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(secret)).build().verify(accessToken);

        String subject = decodedJWT.getSubject();
        String userId = decodedJWT.getClaim(USERID_CLAIM).asString();

        //when
        assertThat(userId).isEqualTo(USERID);
        assertThat(subject).isEqualTo(ACCESS_TOKEN_SUBJECT);
        //then
    }
        

    @Test
    //@Rollback(false)
    public void loginTest() throws Exception {
        //given
        Map<String, String> map = getUserIdPasswordMap(USERID, PASSWORD);

        //when
        MvcResult result = perform(LOGIN_URL, APPLICATION_JSON, map)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        //then
        assertThat(result.getResponse().getHeader(accessHeader)).isNotNull();
        assertThat(result.getResponse().getHeader(refreshHeader)).isNotNull();
    }

    @Test
    public void 유효한토큰들보냈을경우() throws Exception {
        //given
        Map<String, String> map = getUserIdPasswordMap(USERID, PASSWORD);

        MvcResult result = perform(LOGIN_URL, APPLICATION_JSON, map)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        String accessToken = result.getResponse().getHeader(accessHeader);
        String refreshToken = result.getResponse().getHeader(refreshHeader);
        //when
        MvcResult result2 =  mockMvc.perform(get("/member/1")
                            .header(refreshHeader, BEARER + refreshToken)
                            .header(accessHeader, BEARER + accessToken))
                            .andExpect(status().isOk())
                            .andReturn();

        String responseAccessToken = result2.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result2.getResponse().getHeader(refreshHeader);

        //then
        assertThat(responseAccessToken).isNull();
        assertThat(responseRefreshToken).isNull();
        assertThat(result2.getResponse().getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    public void 유효한_refreshToken_유효하지않은_accessToken_보냈을경우_accessToken_재발급() throws Exception {
        //given
        Map<String, String> map = getUserIdPasswordMap(USERID, PASSWORD);

        MvcResult result = perform(LOGIN_URL, APPLICATION_JSON, map)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        String accessToken = "asd";
        String refreshToken = result.getResponse().getHeader(refreshHeader);
        //when

        MvcResult result2 =  mockMvc.perform(get("/member/1")
                        .header(refreshHeader, BEARER + refreshToken)
                        .header(accessHeader, BEARER + accessToken))
                        .andExpect(status().isForbidden())
                        .andReturn();

        String responseAccessToken = result2.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result2.getResponse().getHeader(refreshHeader);

        //then
        assertThat(responseAccessToken).isNotNull();
        assertThat(responseRefreshToken).isNull();
        assertThat(result2.getResponse().getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void 유효하지않은_refreshToken_유효한_accessToken_보냈을경우_인증만성공() throws Exception {
        //given
        Map<String, String> map = getUserIdPasswordMap(USERID, PASSWORD);

        MvcResult result = perform(LOGIN_URL, APPLICATION_JSON, map)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        String accessToken = result.getResponse().getHeader(accessHeader);
        String refreshToken = "asfaf";
        //when

        MvcResult result2 =  mockMvc.perform(get("/member/1")
                        .header(refreshHeader, BEARER + refreshToken)
                        .header(accessHeader, BEARER + accessToken))
                .andExpect(status().isOk())
                .andReturn();

        String responseAccessToken = result2.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result2.getResponse().getHeader(refreshHeader);

        //then
        assertThat(responseAccessToken).isNull();
        assertThat(responseRefreshToken).isNull();
        assertThat(result2.getResponse().getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    public void 유효하지않은_refreshToken_유효하지않은_accessToken_보냈을경우() throws Exception {
        //given
        Map<String, String> map = getUserIdPasswordMap(USERID, PASSWORD);

        MvcResult result = perform(LOGIN_URL, APPLICATION_JSON, map)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        String accessToken = "asfasd";
        String refreshToken = "asfaf";
        //when

        MvcResult result2 =  mockMvc.perform(get("/member/1")
                        .header(refreshHeader, BEARER + refreshToken)
                        .header(accessHeader, BEARER + accessToken))
                .andExpect(status().isUnauthorized())
                .andReturn();

        String responseAccessToken = result2.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result2.getResponse().getHeader(refreshHeader);

        //then
        assertThat(responseAccessToken).isNull();
        assertThat(responseRefreshToken).isNull();
        assertThat(result2.getResponse().getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void 토큰없이요청왔을경우() throws Exception {
        //given
        //when
        MvcResult result2 =  mockMvc.perform(get("/member/1"))
                .andExpect(status().isUnauthorized())
                .andReturn();

        String responseAccessToken = result2.getResponse().getHeader(accessHeader);
        String responseRefreshToken = result2.getResponse().getHeader(refreshHeader);

        //then
        assertThat(responseAccessToken).isNull();
        assertThat(responseRefreshToken).isNull();
        assertThat(result2.getResponse().getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }
}