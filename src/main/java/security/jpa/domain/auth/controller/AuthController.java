package security.jpa.domain.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.jpa.domain.auth.aggregate.dto.SigninDTO;
import security.jpa.domain.auth.aggregate.dto.SignupDTO;
import security.jpa.domain.auth.service.AuthService;
import security.jpa.global.common.response.APIResponse;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "회원가입", description = "회원 가입을 진행합니다.", tags = { "Auth Controller" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST"),
            @ApiResponse(responseCode = "404", description = "NOT FOUND"),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR")
    })
    @PostMapping("/signup")
    public APIResponse<?> signup(@RequestBody SignupDTO signupDTO) {

        authService.signup(signupDTO);

        return APIResponse.ok(
                "회원가입 성공!"
        );
    }

    @Operation(summary = "로그인", description = "로그인을 진행합니다.", tags = { "Auth Controller" })
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST"),
            @ApiResponse(responseCode = "404", description = "NOT FOUND"),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR")
    })
    @PostMapping("/signin")
    public APIResponse<?> signin(@RequestBody SigninDTO signinDTO) {

        String jwt = authService.signin(signinDTO);

        return APIResponse.ok(jwt);
    }
}
