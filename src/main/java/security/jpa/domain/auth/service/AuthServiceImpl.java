package security.jpa.domain.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.jpa.domain.member.repository.MemberRepository;

@Service("AuthServiceImpl")
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    private final MemberRepository memberRepository;
}
