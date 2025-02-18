package com.ll.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
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
                        // 그 외 모든 요청은 인증된 사용자만 접근 가능
                        .anyRequest().authenticated()
                )
                // 세션 관리 설정: JWT를 사용하므로 세션을 생성하지 않음 (STATELESS)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }
}