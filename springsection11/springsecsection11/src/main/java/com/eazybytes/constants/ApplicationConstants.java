package com.eazybytes.constants;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public final class ApplicationConstants {

    public static final String JWT_SECRET_KEY = "JWT_SECRET";
    public static final String JWT_SECRET_DEFAULT_VALUE = String.valueOf(Keys.secretKeyFor(SignatureAlgorithm.HS256)); // 256비트 이상의 키 생성
    public static final String JWT_HEADER = "Authorization";
}
