package security.jpa.domain.member.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.jpa.domain.member.service.MemberService;
import security.jpa.global.common.response.APIResponse;

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
    @GetMapping("/health")
    public APIResponse<?> healthCheck(){
        return APIResponse.ok("You can Do It!!");
    }
}
