package com.auth0.jwt.verification;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class VerificationAndAssertion {

    public static void assertPositive(long leeway) {
        if (leeway < 0) {
            throw new IllegalArgumentException("Leeway value can't be negative.");
        }
    }

    public static void assertNonNull(String name) {
        if (name == null) {
            throw new IllegalArgumentException("The Custom Claim's name can't be null.");
        }
    }

    public static void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    public static void verifyClaims(Clock clock, DecodedJWT jwt, Map<String, Object> claims) throws TokenExpiredException, InvalidClaimException {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            switch (entry.getKey()) {
                case PublicClaims.AUDIENCE:
                    //noinspection unchecked
                    VerificationAndAssertion.assertValidAudienceClaim(jwt.getAudience(), (List<String>) entry.getValue());
                    break;
                case PublicClaims.EXPIRES_AT:
                    assertValidDateClaim(clock, jwt.getExpiresAt(), (Long) entry.getValue(), true);
                    break;
                case PublicClaims.ISSUED_AT:
                    assertValidDateClaim(clock, jwt.getIssuedAt(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.NOT_BEFORE:
                    assertValidDateClaim(clock, jwt.getNotBefore(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.ISSUER:
                    VerificationAndAssertion.assertValidIssuerClaim(jwt.getIssuer(), (List<String>) entry.getValue());
                    break;
                case PublicClaims.JWT_ID:
                    VerificationAndAssertion.assertValidStringClaim(entry.getKey(), jwt.getId(), (String) entry.getValue());
                    break;
                default:
                    VerificationAndAssertion.assertValidClaim(jwt.getClaim(entry.getKey()), entry.getKey(), entry.getValue());
                    break;
            }
        }
    }

    private static void assertValidDateClaim(Clock clock, Date date, long leeway, boolean shouldBeFuture) {
        Date today = clock.getToday();
        today.setTime((long) Math.floor((today.getTime() / 1000) * 1000)); // truncate millis
        if (shouldBeFuture) {
            VerificationAndAssertion.assertDateIsFuture(date, leeway, today);
        } else {
            VerificationAndAssertion.assertDateIsPast(date, leeway, today);
        }
    }

    private static void assertValidClaim(Claim claim, String claimName, Object value) {
        boolean isValid = false;
        if (value instanceof String) {
            isValid = value.equals(claim.asString());
        } else if (value instanceof Integer) {
            isValid = value.equals(claim.asInt());
        } else if (value instanceof Long) {
            isValid = value.equals(claim.asLong());
        } else if (value instanceof Boolean) {
            isValid = value.equals(claim.asBoolean());
        } else if (value instanceof Double) {
            isValid = value.equals(claim.asDouble());
        } else if (value instanceof Date) {
            isValid = value.equals(claim.asDate());
        } else if (value instanceof Object[]) {
            List<Object> claimArr = Arrays.asList(claim.as(Object[].class));
            List<Object> valueArr = Arrays.asList((Object[]) value);
            isValid = claimArr.containsAll(valueArr);
        }

        if (!isValid) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private static void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private static void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private static void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }

    private static void assertValidAudienceClaim(List<String> audience, List<String> value) {
        if (audience == null || !audience.containsAll(value) || audience.size() != value.size()) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }

    private static void assertValidIssuerClaim(List<String> issuer, List<String> value) {
        if (issuer == null || !issuer.containsAll(value) || issuer.size() != value.size()) {
            throw new InvalidClaimException("The Claim 'iss' value doesn't match the required one.");
        }
    }
}
