package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CsrfCookieFilter;
import com.eazybytes.filter.JWTTokenGeneratorFilter;
import com.eazybytes.filter.JWTTokenValidatorFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //CSRF 토큰 요청 속성을 사용하여 토큰 값을 헤더나 매개변수 값으로 해결하는 로직을 포함
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        /* rcc(Requires Channel Configuration */
        // HTTPS 프로토콜을 사용한 보안 유지
        // 안적으면 HTTP, HTTPS 요청 둘다 허용
        http
                // 항상 세션을 생성해 달라고 요청
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(corsConfig -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("https://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));   // 모든 유형의 http 메소드 트래픽 허용
                        config.setAllowCredentials(true);   // UI에서 백엔드로 user 자격 증명이나 기타 적용 가능한 쿠키 수락
                        config.setAllowedHeaders(Collections.singletonList("*"));   // 모든 종류의 헤더를 수락해도 괜찮다.
                        config.setExposedHeaders(Arrays.asList("Authorization"));   // 헤터를 사용하여 JWT 토큰값 전송
                        config.setMaxAge(3600L);    // 1시간
                        return config;
                    }
                }))
                .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        // 아래 API들에 대해서는 CSRF 보호를 무시하도록 지시
                        .ignoringRequestMatchers("/contact", "/register", "/apiLogin")
                        // 로그인 작업 후 처음으로 CSRF 토큰을 생성하는데만 도움을 준다.
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
//                .requiresChannel(rcc -> rcc.anyRequest().requiresSecure())  // Only HTTPS
                .authorizeHttpRequests((requests) -> requests
                        /*.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")  // hasAuthority: 단일 권한 검증
                        .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")    // 여러 권한 중 하나라도 있으면 ㄱㅊ
                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")*/
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession", "/apiLogin").permitAll());
        http.formLogin(withDefaults());
        // hbc: httpBasic() config
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 사용자 비밀 번호가 유출 되었는지 확인하는 메소드
     * From Spring Security 6.3부터 도입
     * @return
     * */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }


    // 인증 메커니즘을 시작하는 역할
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
        // 인증 제공자 객체
        EazyBankProdUsernamePwdAuthenticationProvider authenticationProvider =
                new EazyBankProdUsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);

        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        // provider manager는 Authentication 객체 내부의 비밀번호를 지우지 못하게 설정(유효성 검사)
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return providerManager;
    }
}
