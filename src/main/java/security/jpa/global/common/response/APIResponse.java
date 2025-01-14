package security.jpa.global.common.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import security.jpa.global.common.exception.CommonException;
import security.jpa.global.common.exception.ErrorCode;
import security.jpa.global.common.exception.ExceptionResponse;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class APIResponse<T> {

    @JsonIgnore
    private HttpStatus status;

    @NotNull
    private boolean success;

    @Nullable
    private T result;

    @Nullable
    private ExceptionResponse error;

    // Api 성공시 출력
    public static <T> APIResponse<T> ok(T result) {
        return new APIResponse<>(
                HttpStatus.OK,
                true,
                result,
                null
        );
    }

    // 에러 발생시의 출력 메시지
    public static APIResponse<Object> fail(CommonException e) {
        return new APIResponse<>(
                e.getErrorCode().getHttpStatus(),
                false,
                null,
                ExceptionResponse.of(e.getErrorCode())
        );
    }

    // 400번 에러 처리(프론트엔드)
    public static APIResponse<Object> fail(final MissingServletRequestParameterException e) {
        return new APIResponse<>(
                HttpStatus.BAD_REQUEST,
                false,
                null,
                ExceptionResponse.of(ErrorCode.MISSING_REQUEST_PARAMETER)
        );
    }

    public static APIResponse<Object> fail(final MethodArgumentTypeMismatchException e) {
        return new APIResponse<>(
                HttpStatus.INTERNAL_SERVER_ERROR,
                false,
                null,
                ExceptionResponse.of(ErrorCode.INVALID_PARAMETER_FORMAT)
        );
    }
}
