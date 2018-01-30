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

package com.auth0.jwt.creators;

import static com.auth0.jwt.TimeUtil.generateRandomExpDateInFuture;
import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.jwts.JWT;
import com.auth0.jwt.jwts.RiscJWT;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.text.SimpleDateFormat;
import java.util.*;

public class RiscJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();
    private static final Date nbf = iat;
    private static final String jti = "jti";

    @Test
    public void testRiscJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorBase16Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .signBase16Encoding(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode16Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorBase32Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .signBase32Encoding(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode32Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorJtiNotProvidedButRequired() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Jti has not been set");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorExpNotProvidedButNotRequired() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Jti has not been set");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, -1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("invalid")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testRiscJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("invalid")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testRiscJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testRiscJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testRiscJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withNbf(nbf)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .setIsNoneAlgorithmAllowed(true)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testRiscJwtCreatorArrayClaim() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withArrayClaim("arrayKey", "arrayValue1", "arrayValue2")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", 999)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", 999L)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", true)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", new Date())
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testRiscJwtCreatorExpTimeHasPassed() throws Exception {
        Calendar calendar = Calendar.getInstance();
        calendar.set(2014, Calendar.OCTOBER, 29);

        thrown.expect(TokenExpiredException.class);
        thrown.expectMessage(String.format("The Token has expired on %s", calendar.getTime()));

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = RiscJwtCreator.build()
                .withJWTId(jti)
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withNonStandardClaim("nonStandardClaim", new Date())
                .withExp(calendar.getTime())
                .withIat(iat)
                .sign(algorithm);
        Verification verification = RiscJWT.require(algorithm);
        JWT verifier = verification.createVerifierForRisc(jti, asList("issuer"), asList("audience"), 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    private static void verifyClaims(Map<String,Claim> claims, Date exp) {
        assertTrue(claims.get(PublicClaims.ISSUER).asList(String.class).get(0).equals("issuer"));
        assertTrue(claims.get(PublicClaims.SUBJECT).asList(String.class).get(0).equals("subject"));
        assertTrue(claims.get(PublicClaims.AUDIENCE).asString().equals("audience"));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
        assertTrue(claims.get(PublicClaims.JWT_ID).asString().equals(jti));
    }
}