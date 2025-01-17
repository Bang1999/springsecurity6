package security.jpa.global.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import security.jpa.domain.member.aggregate.entity.Member;
import security.jpa.domain.member.repository.MemberRepository;
import security.jpa.global.common.exception.CommonException;
import security.jpa.global.common.exception.ErrorCode;

@Service(value = "MemberDetailsService")
@RequiredArgsConstructor
public class MemberDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Transactional(readOnly = true)
    @Override
    public MemberDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByLoginId(username)
                .orElseThrow(() -> new CommonException(ErrorCode.USERDETAILS_NOT_FOUND));
        return new MemberDetails(member);
    }
}
