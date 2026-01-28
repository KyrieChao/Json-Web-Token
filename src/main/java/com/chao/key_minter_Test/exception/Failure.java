package com.chao.key_minter_Test.exception;

import java.util.Collection;

public final class Failure {

    private Failure() {
    }

    private static Chain begin() {
        return new Chain();
    }

    public static Chain exists(Object obj) {
        return begin().exists(obj);
    }

    public static Chain blank(String str) {
        return begin().blank(str);
    }

    public static Chain notBlank(String str) {
        return begin().notBlank(str);
    }

    public static Chain notEmpty(String str) {
        return begin().notEmpty(str);
    }

    public static Chain notEmpty(Collection<?> col) {
        return begin().notEmpty(col);
    }

    public static Chain state(boolean b) {
        return begin().state(b);
    }

    public static <T extends Comparable<T>> Chain greater(T a, T b) {
        return begin().greater(a, b);
    }

    public static <T extends Comparable<T>> Chain between(T v, T min, T max) {
        return begin().between(v, min, max);
    }

    public static Chain match(String str, String regex) {
        return begin().match(str, regex);
    }

    public static Chain instanceOf(Object obj, Class<?> type) {
        return begin().instanceOf(obj, type);
    }


    public static Chain contains(Collection<?> c, Object o) {
        return begin().contains(c, o);
    }

    public static Chain notContains(Collection<?> c, Object o) {
        return begin().notContains(c, o);
    }
}

