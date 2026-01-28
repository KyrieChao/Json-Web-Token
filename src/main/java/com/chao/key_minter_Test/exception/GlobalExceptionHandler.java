package com.chao.key_minter_Test.exception;

import com.chao.key_minter_Test.response.ApiResponse;
import com.chao.key_minter_Test.response.HTTPResponseCode;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.stream.Collectors;

@Hidden
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final boolean printMethod;

    public GlobalExceptionHandler(@Value("${exception.print-method:false}") boolean printMethod) {
        this.printMethod = printMethod;
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Void>> handleBusinessException(BusinessException e) {
        HttpStatus status = toHttpStatus(e.getStatusCode());
        logException(e, status);
        return ResponseEntity.status(status)
                .body(ApiResponse.error(e.getStatusCode(), e.getDescription()));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponse<Void>> handleRuntimeException(RuntimeException ex) {
        log.error("RuntimeException Error -> {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(HTTPResponseCode.SYSTEM_ERROR, ex.getMessage(), "系统错误"));
    }

    private void logException(BusinessException e, HttpStatus httpStatus) {
        boolean serverError = httpStatus.is5xxServerError();
        String msg = (printMethod && StringUtils.isNotBlank(e.getMethod()))
                ? "BusinessException @" + e.getMethod() + " - " + e : "BusinessException " + e;
        if (serverError) {
            if (log.isDebugEnabled()) log.error(msg, e);
             else log.error(msg);
        } else {
            log.warn(msg);
        }
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("参数错误: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(HTTPResponseCode.PARAM_ERROR, ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodArgumentNotValid(MethodArgumentNotValidException ex) {
        FieldError fe = ex.getBindingResult().getFieldError();
        String msg = fe != null ? fe.getField() + ": " + fe.getDefaultMessage() : "参数校验失败";
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(HTTPResponseCode.PARAM_ERROR, msg));
    }

    @ExceptionHandler(BindException.class)
    public ResponseEntity<ApiResponse<Void>> handleBindException(BindException ex) {
        FieldError fe = ex.getBindingResult().getFieldError();
        String msg = fe != null ? fe.getField() + ": " + fe.getDefaultMessage() : "参数绑定失败";
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(HTTPResponseCode.PARAM_ERROR, msg));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleConstraintViolation(ConstraintViolationException ex) {
        String msg = ex.getConstraintViolations().stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .collect(Collectors.joining("; "));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(HTTPResponseCode.PARAM_ERROR, msg));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResponse<Void>> handleMissingParam(MissingServletRequestParameterException ex) {
        String msg = "缺少参数: " + ex.getParameterName();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(HTTPResponseCode.PARAM_MISSING, msg));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        String msg = "不支持的方法: " + ex.getMethod();
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ApiResponse.error(HTTPResponseCode.METHOD_NOT_ALLOWED, msg));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex) {
        String msg = "不支持的媒体类型: " + ex.getContentType();
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(ApiResponse.error(HTTPResponseCode.UNSUPPORTED_MEDIA_TYPE, msg));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleMessageNotReadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(HTTPResponseCode.PARAM_INVALID, "请求体不可读"));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoHandlerFound(NoHandlerFoundException ex) {
        String msg = "接口不存在: " + ex.getRequestURL();
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(HTTPResponseCode.API_NOT_FOUND, msg));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleException(Exception ex) {
        log.error("Unhandled Exception -> {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error(HTTPResponseCode.SYSTEM_ERROR, ex.getMessage(), "系统错误"));
    }

    private HttpStatus toHttpStatus(HTTPResponseCode code) {
        int c = code.getCode();
        if (c >= 100 && c <= 599) return HttpStatus.valueOf(c);
        if (c >= 40000 && c < 40100) return HttpStatus.BAD_REQUEST;
        if (c >= 40100 && c < 40200) return HttpStatus.UNAUTHORIZED;
        if (c >= 40300 && c < 40400) return HttpStatus.FORBIDDEN;
        if (c >= 40400 && c < 40500) return HttpStatus.NOT_FOUND;
        if (c >= 41500 && c < 41600) return HttpStatus.UNSUPPORTED_MEDIA_TYPE;
        if (c >= 42200 && c < 42300) return HttpStatus.UNPROCESSABLE_ENTITY;
        if (c >= 42900 && c < 43000) return HttpStatus.TOO_MANY_REQUESTS;
        if (c >= 50000 && c < 50100) return HttpStatus.INTERNAL_SERVER_ERROR;
        if (c >= 60000 && c < 70000) return HttpStatus.BAD_REQUEST;
        if (c >= 70000 && c < 80000) return HttpStatus.BAD_REQUEST;
        if (c >= 80000 && c < 90000) return HttpStatus.SERVICE_UNAVAILABLE;
        if (c >= 90000 && c < 100000) return HttpStatus.UNPROCESSABLE_ENTITY;
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
