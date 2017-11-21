package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.jwts.JWT;
import org.apache.commons.codec.binary.Base64;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Date;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWTTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testWithNbf() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).withNbf(5);
    }

    @Test
    public void testCreateVerifierForRisc() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).createVerifierForRisc(null, null, null, 5, 5, 5);
    }

    @Test
    public void testCreateVerifierForScoped() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).createVerifierForScoped(null, null, null, 5, 5);
    }

    @Test
    public void testCreateVerifierForImplicit() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).createVerifierForImplicit(null, null,  5);
    }

    @Test
    public void testCreateVerifierForFB() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).createVerifierForFb(null, null);
    }

    @Test
    public void testCreateVerifierForAccess() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).createVerifierForAccess(null, null, 5, 5);
    }

    @Test
    public void testWithUserId() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).withUserId(null);
    }

    @Test
    public void testWithAppId() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        JWT.require(Algorithm.none()).withAppId(null);
    }

    @Test
    public void testWithSubjectId() {
        JWT.require(Algorithm.none()).withSubject("subject1", "subject2");
    }

    @Test
    public void testAcceptLeeway() {
        JWT.require(Algorithm.none()).acceptLeeway(5);
    }

    @Test
    public void testAcceptNotBefore() {
        JWT.require(Algorithm.none()).acceptNotBefore(5);
    }

    @Test
    public void testWithJWTId() {
        JWT.require(Algorithm.none()).withJWTId("jwtId");
    }

    @Test
    public void testJWTNonStandardClaimBoolean() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", true);
    }

    @Test
    public void testJWTNonStandardClaimInteger() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", 5);
    }

    @Test
    public void testJWTNonStandardClaimLong() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", 5L);
    }

    @Test
    public void testJWTNonStandardClaimDouble() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", 9.99);
    }

    @Test
    public void testJWTNonStandardClaimString() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue");
    }

    @Test
    public void testJWTNonStandardClaimDate() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", new Date());
    }

    @Test
    public void testJWTWithArrayClaimStrings() throws Exception {
        JWT.require(Algorithm.none()).withArrayClaim("arrayKey", "arrayValue1", "arrayValue2");
    }

    @Test
    public void testJWTWithArrayClaimIntegers() throws Exception {
        JWT.require(Algorithm.none()).withArrayClaim("arrayKey", 1, 2).build();
    }

    @Test
    public void testJWTNullAlgorithm() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Algorithm cannot be null.");
        JWT.require(null);
    }
}
