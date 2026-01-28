package com.chao.key_minter_Test.exception;

import com.chao.key_minter_Test.response.HTTPResponseCode;
import lombok.Builder;
import lombok.Getter;

import java.io.Serial;
import java.io.Serializable;

/**
 * 自定义异常类
 */
@Getter
public class BusinessException extends RuntimeException implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
    private final HTTPResponseCode statusCode;
    private final String description;
    private final String method;

    private BusinessException(HTTPResponseCode statusCode, String description, String method) {
        super(statusCode != null ? statusCode.getMessage() : "Unknown error");
        this.statusCode = statusCode;
        this.description = description;
        this.method = method;
    }

    public static BusinessException of(HTTPResponseCode code) {
        return builder().code(code).build();
    }

    public static BusinessException of(HTTPResponseCode code, String description) {
        return builder().code(code).description(description).build();
    }

    public static BusinessException of(HTTPResponseCode code, String description, Object... args) {
        return builder()
                .code(code)
                .description(String.format(description, args))
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }
    public static class Builder {
        private HTTPResponseCode statusCode;
        private String description;
        private String method;

        public Builder code(HTTPResponseCode code) {
            this.statusCode = code;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public BusinessException build() {
            if (statusCode == null) throw new IllegalArgumentException("statusCode 不能为空");
            if (description == null) description = statusCode.getDescription();
            return new BusinessException(statusCode, description, method);
        }
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        if (FailureBuilder.PRINT_METHOD || statusCode == HTTPResponseCode.SYSTEM_ERROR) {
            return super.fillInStackTrace();
        }
        return this;
    }

    @Override
    public String toString() {
        if (method == null) {
            return "BusinessException{code=%d, message=%s, description='%s'}"
                    .formatted(statusCode.getCode(), statusCode.getMessage(), description);
        }
        return "BusinessException{code=%d, message=%s, description='%s', method='%s'}"
                .formatted(statusCode.getCode(), statusCode.getMessage(), description, method);
    }
}

