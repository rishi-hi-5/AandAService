package com.reftech.backend.anaservice.utility;

public class StringIntegerUtility {

    public static String incrementValue(String value) {
        return String.valueOf(Integer.parseInt(value) + 1);
    }
}
