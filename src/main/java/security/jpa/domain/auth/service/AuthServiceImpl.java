package security.jpa.domain.auth.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.jpa.domain.auth.aggregate.dto.SigninDTO;
import security.jpa.domain.auth.aggregate.dto.SignupDTO;
import security.jpa.domain.member.aggregate.entity.Member;
import security.jpa.domain.member.repository.MemberRepository;
import security.jpa.global.common.exception.CommonException;
import security.jpa.global.common.exception.ErrorCode;
import security.jpa.global.security.service.MemberDetails;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

@Service("AuthServiceImpl")
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    @Value("${jwt.secret-key}")
    private String jwtSecretKey;

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public void signup(SignupDTO signupDTO) {

        String hashPwd = passwordEncoder.encode(signupDTO.getPassword());

        // 회원 정보 저장
        Member member = Member.builder()
                              .name(signupDTO.getName())
                              .loginId(signupDTO.getLoginId())
                              .password(hashPwd)
                              .role("ROLE_USER")
                              .age(signupDTO.getAge())
                              .gender(signupDTO.getGender())
                              .build();

        memberRepository.save(member);
    }

    @Override
    @Transactional
    public String signin(SigninDTO signinDTO) {

        // 사용자 인증
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                signinDTO.getLoginId(), signinDTO.getPassword());
        Authentication authenticationResponse = authenticationManager.authenticate(authentication);

        if(authenticationResponse == null || !authenticationResponse.isAuthenticated()) {
            throw new CommonException(ErrorCode.LOGIN_FAILURE);
        }

        // 인증된 사용자 정보 SecurityContext에 저장
        SecurityContextHolder.getContext().setAuthentication(authenticationResponse);

        // JWT 생성
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));

        String jwt = Jwts.builder()
                            .setIssuer("Bang99")
                            .setSubject("JWT Token")
                            .claim("username", ((MemberDetails) authenticationResponse.getPrincipal()).getUsername()) // 추가: 사용자 고유 식별자
                            .claim("authorities", authenticationResponse.getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
                            .setIssuedAt(new java.util.Date())
                            .setExpiration(new java.util.Date((new java.util.Date()).getTime() + 30000000L)) // 만료시간 8시간
                            .signWith(secretKey)
                            .compact();

        return jwt;
    }
}
