package security.jpa.domain.sample.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import security.jpa.global.common.response.APIResponse;

@RestController
@RequestMapping("/sample")
public class SampleController {

    @Operation(summary = "Health Check", description = "Health 체크를 위함입니다.", tags = { "Sample Controller" })
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
