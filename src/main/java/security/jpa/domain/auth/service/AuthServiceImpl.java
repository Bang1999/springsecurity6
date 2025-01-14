package security.jpa.domain.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.jpa.domain.auth.aggregate.dto.SignupDTO;
import security.jpa.domain.member.aggregate.entity.Member;
import security.jpa.domain.member.repository.MemberRepository;

@Service("AuthServiceImpl")
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void signup(SignupDTO signupDTO) {

        String hashPwd = passwordEncoder.encode(signupDTO.getPassword());

        Member member = Member.builder()
                              .name(signupDTO.getName())
                              .loginId(signupDTO.getLoginId())
                              .password(hashPwd)
                              .role("ROLE_USER")
                              .build();

        memberRepository.save(member);
    }
}
