package security.jpa.global.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import security.jpa.global.security.service.MemberDetails;
import security.jpa.global.security.service.MemberDetailsService;

@Component
@Profile("dev")
@RequiredArgsConstructor
public class DevUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final MemberDetailsService memberDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();

        MemberDetails memberDetails = memberDetailsService.loadUserByUsername(username);

        // 비밀번호 맞는지 확인 로직
        if(!passwordEncoder.matches(pwd, memberDetails.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        // Principal과 GrantedAuthority 설정
        return new UsernamePasswordAuthenticationToken(memberDetails, null, memberDetails.getAuthorities());
    }

    // 추후에 여기에 OAuth2.0 추가 가능 할 듯
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
