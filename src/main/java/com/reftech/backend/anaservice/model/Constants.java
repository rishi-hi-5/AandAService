package com.reftech.backend.anaservice.model;

public class Constants {

    public static final int EXPIRY_DURATION = 5;
    public static final int RATE_COUNT = 5;
    public static final String INITIAL_COUNT = "1";
    public static final String BLACKLIST_PREFIX = "BLACKLIST:";
    public static final Long BLACKLIST_DURATION = 1000L * 60 * 30;
    public static final Long TOKEN_EXPIRATION = 1000L * 60 * 60 * 10;

    public static final Long REFRESH_TOKEN_EXPIRATION = 1000L * 60 * 60 * 24 * 30;
}
