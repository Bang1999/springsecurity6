package security.jpa.domain.member.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.jpa.domain.member.service.MemberService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/member")
public class MemberContoller {

    private final MemberService memberService;
}
