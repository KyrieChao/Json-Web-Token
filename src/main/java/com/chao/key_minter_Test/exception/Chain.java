package com.chao.key_minter_Test.exception;


import com.chao.key_minter_Test.response.HTTPResponseCode;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

public final class Chain {
    private boolean alive = true;

    public Chain exists(Object obj) {
        this.alive = this.alive && (obj != null);
        return this;
    }

    public Chain notEmpty(String str) {
        this.alive = this.alive && (str != null && !str.trim().isEmpty());
        return this;
    }

    public Chain blank(String str) {
        this.alive = this.alive && (str == null || str.trim().isEmpty());
        return this;
    }

    public Chain notBlank(String str) {
        this.alive = this.alive && (str != null && !str.trim().isEmpty());
        return this;
    }

    public Chain notEmpty(Collection<?> col) {
        this.alive = this.alive && (col != null && !col.isEmpty());
        return this;
    }

    public Chain state(boolean b) {
        this.alive = this.alive && b;
        return this;
    }

    public <T extends Comparable<T>> Chain greater(T a, T b) {
        this.alive = this.alive && (a != null && b != null && a.compareTo(b) > 0);
        return this;
    }

    public <T extends Comparable<T>> Chain between(T v, T min, T max) {
        this.alive = this.alive && (v != null && min != null && max != null && v.compareTo(min) >= 0 && v.compareTo(max) <= 0);
        return this;
    }

    public Chain match(String str, String regex) {
        this.alive = this.alive && (str != null && regex != null && str.matches(regex));
        return this;
    }

    public Chain instanceOf(Object obj, Class<?> type) {
        this.alive = this.alive && (type != null && type.isInstance(obj));
        return this;
    }

    public Chain orElse(HTTPResponseCode code) {
        if (!alive) {
            end();
            throw FailureBuilder.build(code, code.getDescription());
        }
        end();
        return this;
    }

    public Chain contains(Collection<?> c, Object o) {
        this.alive = this.alive && (c != null && c.contains(o));
        return this;
    }

    public Chain notContains(Collection<?> c, Object o) {
        this.alive = this.alive && (c != null && !c.contains(o));
        return this;
    }

    public Chain allMatch(Collection<?> collection, Predicate<Object> predicate) {
        this.alive = this.alive && (collection != null && collection.stream().allMatch(predicate));
        return this;
    }

    public Chain anyMatch(Collection<?> collection, Predicate<Object> predicate) {
        this.alive = this.alive && (collection != null && collection.stream().anyMatch(predicate));
        return this;
    }

    public Chain orElse(HTTPResponseCode code, String msg) {
        if (!alive) {
            end();
            throw FailureBuilder.build(code, msg);
        }
        end();
        return this;
    }

    public Chain orElse(Consumer<BusinessException.Builder> consumer) {
        if (!alive) {
            BusinessException.Builder builder = BusinessException.builder();
            consumer.accept(builder);
            throw builder.build();
        }
        end();
        return this;
    }

    public Chain orElseThrow(Supplier<BusinessException> exceptionSupplier) {
        if (!alive) {
            end();
            throw exceptionSupplier.get();
        }
        end();
        return this;
    }

    private void end() {
        FailureBuilder.clearMethodContext();
    }
}
