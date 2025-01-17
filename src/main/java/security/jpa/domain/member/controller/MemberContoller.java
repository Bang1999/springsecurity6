package security.jpa.domain.member.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import security.jpa.domain.member.service.MemberService;
import security.jpa.global.common.response.APIResponse;
import security.jpa.global.security.service.MemberDetails;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberContoller {

    private final MemberService memberService;

    @Operation(summary = "본인 정보 조회", description = "본인 정보를 조회합니다.", tags = { "Member Controller" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST"),
            @ApiResponse(responseCode = "404", description = "NOT FOUND"),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR")
    })
    @GetMapping("/info")
    public APIResponse<?> healthCheck(@AuthenticationPrincipal MemberDetails memberDetails){

        String a = memberDetails.getUsername();
        String b = memberDetails.getPassword();
        String c = memberDetails.getAge();
        String d = memberDetails.getGender();

        Map<String, String> map = new HashMap<>();
        map.put("username", a);
        map.put("password", b);
        map.put("age", c);
        map.put("gender", d);

        return APIResponse.ok(map);
    }
}
