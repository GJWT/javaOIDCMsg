package com.auth0.jwt.interfaces;

import com.auth0.jwt.jwts.JWT;

import java.util.Date;
import java.util.List;

public interface Verification {
    Verification withIssuer(String... issuer);

    Verification withSubject(String... subject);

    Verification withAudience(String... audience);

    Verification acceptLeeway(long leeway) throws IllegalArgumentException;

    Verification acceptExpiresAt(long leeway) throws IllegalArgumentException;

    Verification acceptNotBefore(long leeway) throws IllegalArgumentException;

    Verification acceptIssuedAt(long leeway) throws IllegalArgumentException;

    Verification withJWTId(String jwtId);

    Verification withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Integer value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Long value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Double value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, String value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Date value) throws IllegalArgumentException;

    Verification withArrayClaim(String name, String... items) throws IllegalArgumentException;

    Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException;

    Verification withNbf(long nbf);

    Verification createVerifierForScoped(String scope, List<String> issuer,
                                         List<String> audience, long expLeeway, long iatLeeway);

    Verification createVerifierForImplicit(List<String> issuer,
                                           List<String> audience, long iatLeeway);

    Verification createVerifierForFb(String userId, String appId);

    Verification withUserId(String userId);

    Verification withAppId(String appId);

    JWT build();
}
