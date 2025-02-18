package com.ll.backend.config;

import com.ll.backend.jwt.JwtFilter;
import com.ll.backend.jwt.JwtUtil;
import com.ll.backend.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(request -> {

                    CorsConfiguration configuration = new CorsConfiguration();

                    // 허용할 출처 설정 (React 앱의 주소)
                    configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                    // 모든 HTTP 메서드 허용
                    configuration.setAllowedMethods(Collections.singletonList("*"));
                    // 인증 정보 (쿠키 등) 허용
                    configuration.setAllowCredentials(true);
                    // 모든 헤더 허용
                    configuration.setAllowedHeaders(Collections.singletonList("*"));
                    // pre-flight 요청 결과를 1시간 동안 캐시(pre-flight: 실제 요청 전에 브라우저가 보내는 OPTIONS 요청.)
                    configuration.setMaxAge(3600L);
                    // 클라이언트에서 접근 가능한 헤더 설정
                    configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                    return configuration;
                })))
                // CSRF(Cross-Site Request Forgery) 보호 기능 비활성.
                .csrf(AbstractHttpConfigurer::disable)
                // X-Frame-Options 헤더 설정: H2 콘솔 접근을 위해 SAMEORIGIN으로 설정
                .headers(headers -> headers
                        .addHeaderWriter(new XFrameOptionsHeaderWriter(
                                XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)
                        )
                )
                // 폼 로그인 비활성화: JWT를 사용하므로 폼 로그인은 사용하지 않음
                .formLogin(AbstractHttpConfigurer::disable)
                // HTTP Basic 인증 비활성화: JWT를 사용하므로 Basic 인증은 사용하지 않음
                .httpBasic(AbstractHttpConfigurer::disable)
                // URL별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // 로그인, 홈, 회원가입 페이지, h2-console은 모든 사용자에게 허용
                        .requestMatchers("/login", "/", "/join", "/h2-console/**").permitAll()
                        // 관리자 페이지는 ADMIN 역할을 가진 사용자만 접근 가능
                        .requestMatchers("/admin").hasRole("ADMIN")
                        // Refresh 토큰으로 Access 토큰을 재발급 하기 위한 경로는 모든 사용자에게 허용
                        .requestMatchers("/reissue").permitAll()
                        // 그 외 모든 요청은 인증된 사용자만 접근 가능
                        .anyRequest().authenticated()
                )
                //JWTFilter 등록
                .addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class)
                // 커스텀 로그인 필터. 기본 로그인 필터와 같은 위치에 추가.
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class)
                // 세션 관리 설정: JWT를 사용하므로 세션을 생성하지 않음 (STATELESS)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }
}