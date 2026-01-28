package com.chao.key_minter_Test.exception;

import com.chao.key_minter_Test.response.HTTPResponseCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public final class FailureBuilder {

    private static final ThreadLocal<Boolean> METHOD_CACHE_ENABLED = ThreadLocal.withInitial(() -> Boolean.FALSE);
    private static final ThreadLocal<String> CACHED_METHOD_NAME = new ThreadLocal<>();
    private static final Map<String, String> METHOD_NAME_CACHE = new ConcurrentHashMap<>(256);
    private static final int MAX_CACHE_SIZE = 1000;
    public static volatile boolean PRINT_METHOD = false;

    @Value("${exception.print-method:false}")
    public void setPrintMethod(boolean printMethod) {
        PRINT_METHOD = printMethod;
        log.info("Failure DEBUG = {}", PRINT_METHOD);
    }

    private FailureBuilder() {
    }

    public static void setCurrentMethod(String methodName) {
        if (PRINT_METHOD) {
            CACHED_METHOD_NAME.set(methodName);
            METHOD_CACHE_ENABLED.set(true);
            if (METHOD_NAME_CACHE.size() < MAX_CACHE_SIZE) {
                METHOD_NAME_CACHE.putIfAbsent(methodName, methodName);
            }
        }
    }

    public static void clearMethodContext() {
        CACHED_METHOD_NAME.remove();
        METHOD_CACHE_ENABLED.remove();
    }

    public static BusinessException build(HTTPResponseCode code, String description) {
        String method = resolveMethodName();
        return BusinessException.builder()
                .code(code)
                .description(description)
                .method(method)
                .build();
    }

    private static String resolveMethodName() {
        if (!PRINT_METHOD) return null;

        if (Boolean.TRUE.equals(METHOD_CACHE_ENABLED.get())) {
            return CACHED_METHOD_NAME.get();
        }
        String methodName = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(stream -> stream
                        .filter(f -> !f.getClassName().equals(FailureBuilder.class.getName()))
                        .filter(f -> !f.getClassName().equals(Chain.class.getName()))
                        .filter(f -> !f.getClassName().equals(Failure.class.getName()))
                        .findFirst()
                        .map(f -> {
                            String cls = f.getClassName();
                            int idx = cls.lastIndexOf('.');
                            String simple = idx >= 0 ? cls.substring(idx + 1) : cls;
                            return simple + "#" + f.getMethodName();
                        })
                        .orElse("unknown"));
        if (METHOD_NAME_CACHE.size() < MAX_CACHE_SIZE) {
            METHOD_NAME_CACHE.putIfAbsent(methodName, methodName);
        }
        return methodName;
    }
}
