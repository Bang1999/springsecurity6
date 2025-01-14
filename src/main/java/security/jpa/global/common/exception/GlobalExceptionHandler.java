package security.jpa.global.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import security.jpa.global.common.response.ApiResponse;

@Slf4j
// 모든 rest컨트롤러에서 발생하는 예외 처리
@RestControllerAdvice(basePackages = "stanl_2.weshareyou")
public class GlobalExceptionHandler {

    // 지원되지 않는 HTTP 메소드를 사용할 때 발생하는 예외
    @ExceptionHandler(value = {NoHandlerFoundException.class, HttpRequestMethodNotSupportedException.class})
    public ApiResponse<?> handleNoPageFoundException(Exception e) {
        log.error("handleNoPageFoundException() in GlobalExceptionHandler throw NoHandlerFoundException : {}"
                , e.getMessage());
        return ApiResponse.fail(new CommonException(ErrorCode.WRONG_ENTRY_POINT));
    }

    // 메소드의 인자 타입이 일치하지 않을 때 발생하는 예외
    @ExceptionHandler(value = {MethodArgumentTypeMismatchException.class})
    public ApiResponse<?> handleArgumentNotValidException(MethodArgumentTypeMismatchException e) {
        log.error("handleArgumentNotValidException() in GlobalExceptionHandler throw MethodArgumentTypeMismatchException : {}"
                , e.getMessage());
        return ApiResponse.fail(e);
    }

    // 필수 파라미터가 누락되었을 때 발생하는 예외
    @ExceptionHandler(value = {MissingServletRequestParameterException.class})
    public ApiResponse<?> handleArgumentNotValidException(MissingServletRequestParameterException e) {
        log.error("handleArgumentNotValidException() in GlobalExceptionHandler throw MethodArgumentNotValidException : {}"
                , e.getMessage());
        return ApiResponse.fail(e);
    }

    // 사용자 정의 예외 처리
    @ExceptionHandler(value = {CommonException.class})
    public ApiResponse<?> handleCustomException(CommonException e) {
        log.error("handleCustomException() in GlobalExceptionHandler: {}", e.getMessage());
        return ApiResponse.fail(e);
    }

    // 서버 내부 오류시 작동
    @ExceptionHandler(value = {Exception.class})
    public ApiResponse<?> handleServerException(Exception e) {
        log.info("occurred exception in handleServerError = {}", e.getMessage());
        e.printStackTrace();
        return ApiResponse.fail(new CommonException(ErrorCode.INTERNAL_SERVER_ERROR));
    }

    // 데이터 무결성 위반 예외 처리기 추가
    @ExceptionHandler(value = {DataIntegrityViolationException.class})
    public ApiResponse<?> handleDataIntegrityViolationException(DataIntegrityViolationException e) {
        log.error("handleDataIntegrityViolationException() in GlobalExceptionHandler : {}", e.getMessage());
        return ApiResponse.fail(new CommonException(ErrorCode.DATA_INTEGRITY_VIOLATION));
    }

    @ExceptionHandler(value = {MethodArgumentNotValidException.class})
    public ApiResponse<?> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        log.error("유효성 검사 실패: {}", e.getMessage());
        return ApiResponse.fail(new CommonException(ErrorCode.VALIDATION_FAIL));
    }
}
