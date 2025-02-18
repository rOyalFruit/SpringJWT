package com.ll.backend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        corsRegistry.addMapping("/**")            // 모든 경로에 대해 CORS 설정을 적용
                .allowedOrigins("http://localhost:3000");  // React 앱이 실행되는 주소에서의 요청을 허용
    }
}
