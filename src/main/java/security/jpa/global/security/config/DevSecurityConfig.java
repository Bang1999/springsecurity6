package security.jpa.global.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import security.jpa.global.common.exception.CommonException;
import security.jpa.global.common.exception.ErrorCode;
import security.jpa.global.security.filter.JWTTokenValidatorFilter;
import security.jpa.global.security.service.MemberDetailsService;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@Configuration
@Profile("dev")
public class DevSecurityConfig {

    private final MemberDetailsService memberDetailsService;

    public DevSecurityConfig(MemberDetailsService memberDetailsService) {
        this.memberDetailsService = memberDetailsService;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(csrfConfig -> csrfConfig.disable());
        http.cors(corsConfig -> corsConfig.configurationSource(corsConfigurationSource()))
                // HTTPS가 아닌 요청도 허용
                .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure())
                .addFilterBefore(new JWTTokenValidatorFilter(memberDetailsService), BasicAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // 인증 없이 접근 가능한 API 설정
//                        .anyRequest().permitAll())
                        .requestMatchers("/swagger-ui/**","/v3/api-docs/**", "/swagger-resources/**", "/auth/signup", "/auth/signin", "/member/check").permitAll()
                                .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            log.error("Authentication error: {}", authException.getMessage());
                            throw new CommonException(ErrorCode.LOGIN_FAILURE);
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            log.error("Access denied: {}", accessDeniedException.getMessage());
                            throw new CommonException(ErrorCode.FORBIDDEN_ROLE);
                        }));
        ;

        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.singletonList("http://localhost:5173"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowCredentials(true);
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        config.setExposedHeaders(Collections.singletonList("Authorization"));
        config.setMaxAge(3600L);

        return request -> config;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 사용자 비밀 번호가 유출 되었는지 확인하는 메소드
     * From Spring Security 6.3부터 도입
     * */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }

    @Bean
    public AuthenticationManager authenticationManager(MemberDetailsService memberDetailsService, PasswordEncoder passwordEncoder){

        // 인증 제공자 객체
        DevUsernamePwdAuthenticationProvider authenticationProvider
                = new DevUsernamePwdAuthenticationProvider(memberDetailsService, passwordEncoder);

        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false);
        return providerManager;
    }
}
