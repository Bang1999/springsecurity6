package security.jpa.global.common.exception;

import lombok.Getter;

@Getter
public class ExceptionResponse {
    private final Integer code;
    private final String message;

    public ExceptionResponse(ErrorCode errorCode){
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    public static ExceptionResponse of(ErrorCode errorCode){
        return new ExceptionResponse(errorCode);
    }

}
