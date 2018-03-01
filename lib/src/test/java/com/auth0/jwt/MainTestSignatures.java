// Copyright (c) 2017 The Authors of 'JWTS for Java'
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package com.auth0.jwt;

import static com.auth0.jwt.TimeUtil.generateRandomExpDateInFuture;
import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.creators.GoogleJwtCreator;
import com.auth0.jwt.creators.GoogleJwtCreatorTest;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.impl.Claims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.jwts.GoogleJWT;
import com.auth0.jwt.jwts.JWT;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class MainTestSignatures {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private Date exp = generateRandomExpDateInFuture();
    private Date iat = generateRandomIatDateInPast();

    @Test
    public void testComplainOnNone() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Algorithm cannot be null.");

        String token = JWT.create().withIssuer("accounts.fake.com").withSubject("subject")
                .withAudience("audience")
                .sign(null);
        GoogleVerification verification = GoogleJWT.require(null);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("accounts.fake.com"), asList("audience"),
                 GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testVerifyingWithEmptyKey() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Empty key");
        Algorithm algorithm = Algorithm.HMAC256("");
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL,asList("accounts.fake.com"), asList("audience"),
                 GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToMultipleKeys() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withSubject("subject")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withIssuer("issuer")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("issuer", "issuer2"), asList("audience", "audience2", "audience3"),
                GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String,Claim> claims = jwt.getClaims();
        assertTrue(claims.get(GoogleJwtCreatorTest.PICTURE).asString().equals(GoogleJwtCreatorTest.PICTURE));
        assertTrue(claims.get(GoogleJwtCreatorTest.EMAIL).asString().equals(GoogleJwtCreatorTest.EMAIL));
        String issuer = claims.get(Claims.ISSUER).asString();
        assertTrue(issuer.equals("issuer"));
        String subject = claims.get(Claims.SUBJECT).asString();
        assertTrue(subject.equals("subject"));
        List<String> audience = claims.get(Claims.AUDIENCE).asList(String.class);
        assertTrue(audience.get(0).equals("audience"));
        assertTrue(audience.get(1).equals("audience2"));
        assertTrue(claims.get(Claims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
        assertTrue(claims.get(GoogleJwtCreatorTest.NAME).asString().equals(GoogleJwtCreatorTest.NAME));
    }

    @Test
    public void testConfigurableToIncorrectNumberMultipleKeysForAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withSubject("subject")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withIssuer("issuer")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("issuer", "issuer2"), asList("audience"),
                GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testConfigurableToIncorrectValueMultipleKeysForAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = GoogleJwtCreator.build()
                .withPicture(GoogleJwtCreatorTest.PICTURE)
                .withEmail(GoogleJwtCreatorTest.EMAIL)
                .withSubject("subject")
                .withAudience("audience", "audience2")
                .withExp(exp)
                .withIat(iat)
                .withName(GoogleJwtCreatorTest.NAME)
                .withIssuer("issuer")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(GoogleJwtCreatorTest.PICTURE, GoogleJwtCreatorTest.EMAIL, asList("issuer", "issuer2"), asList("audience", "audience3"),
                GoogleJwtCreatorTest.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }
}