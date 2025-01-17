package security.jpa.domain.member.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.jpa.domain.member.aggregate.entity.Member;
import security.jpa.domain.member.repository.MemberRepository;

@Service("MemberServiceImpl")
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService{

    private final MemberRepository memberRepository;

    @Override
    public void check(String a) {
        Member ss = memberRepository.findByLoginId(a).orElseThrow();

        System.out.println("$$$$$$$$$$$$$$$$");
        System.out.println(ss);
        System.out.println(ss.getName());
    }
}
