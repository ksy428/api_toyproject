package seyoung.toyproject.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import seyoung.toyproject.domain.member.repository.MemberRepository;
import seyoung.toyproject.global.filter.JsonUsernamePasswordAuthenticationFilter;
import seyoung.toyproject.global.filter.JwtAuthenticationProcessingFilter;
import seyoung.toyproject.global.handler.CustomLogoutHandler;
import seyoung.toyproject.global.handler.CustomLogoutSuccessHandler;
import seyoung.toyproject.global.handler.LoginFailureHandler;
import seyoung.toyproject.global.handler.LoginSuccessJWTProvideHandler;
import seyoung.toyproject.global.jwt.service.JwtService;
import seyoung.toyproject.global.redis.service.RedisService;
import seyoung.toyproject.global.security.service.UserDetailsServiceImpl;


@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
@Slf4j
public class WebSecurityConfig implements WebMvcConfigurer {
    private final ObjectMapper objectMapper;
    private final UserDetailsServiceImpl userDetailsService;
    private final MemberRepository memberRepository;
    private final JwtService jwtService;
    private final RedisService redisService;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true)
                .exposedHeaders("Authorization","Authorization-refresh");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .formLogin((formLogin)-> formLogin.disable())
                .httpBasic((httpBasic) -> httpBasic.disable())
                .csrf((csrf) -> csrf.disable())
                .sessionManagement((sessionManagement) -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .requestMatchers("/", "/signUp").permitAll()
                                .anyRequest().authenticated()
                )
                // LogoutFilter -> jwtAuthenticationProcessingFilter -> jsonUsernamePasswordLoginFilter 순서
                .addFilterAfter(jwtAuthenticationProcessingFilter(), LogoutFilter.class)
                .addFilterAfter(jsonUsernamePasswordLoginFilter(), LogoutFilter.class)
                .logout((logoutConfigurer ) ->
                        logoutConfigurer
                                .logoutUrl("/logout")
                                .addLogoutHandler(customLogoutHandler())
                                .logoutSuccessHandler(customLogoutSuccessHandler())
                                .invalidateHttpSession(true)
                                .permitAll()
                );
        return http.build();
    }



    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);

        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessJWTProvideHandler loginSuccessJWTProvideHandler(){
        return new LoginSuccessJWTProvideHandler(jwtService, memberRepository);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler(){
        return new LoginFailureHandler();
    }

    @Bean
    public JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter(){
        JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter = new JsonUsernamePasswordAuthenticationFilter(objectMapper);
        jsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        jsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessJWTProvideHandler());
        jsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return jsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter(){
        JwtAuthenticationProcessingFilter jsonUsernamePasswordLoginFilter = new JwtAuthenticationProcessingFilter(jwtService, memberRepository, redisService);
        return jsonUsernamePasswordLoginFilter;
    }

    @Bean
    public CustomLogoutHandler customLogoutHandler() {return new CustomLogoutHandler(jwtService, redisService, memberRepository);}
    @Bean
    public CustomLogoutSuccessHandler customLogoutSuccessHandler() {return new CustomLogoutSuccessHandler(jwtService, redisService);}
}
