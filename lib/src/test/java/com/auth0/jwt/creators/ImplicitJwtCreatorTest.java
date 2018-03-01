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

import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;

import com.auth0.jwt.TimeUtil;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.RequiredClaimException;
import com.auth0.jwt.impl.Claims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.jwts.ImplicitJWT;
import com.auth0.jwt.jwts.JWT;
import java.util.Date;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ImplicitJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date iat = generateRandomIatDateInPast();


    @Test
    public void testImplicitJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorBase16Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .signBase16Encoding(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode16Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorBase32Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .signBase32Encoding(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode32Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("invalid")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("invalid")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorIssuerNotProvided() throws Exception {
        thrown.expect(RequiredClaimException.class);
        thrown.expectMessage("Standard claim: iss has not been set");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .setIsNoneAlgorithmAllowed(false)
                .withIat(iat)
                .sign(algorithm);

        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testImplicitJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .setIsNoneAlgorithmAllowed(true)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorArrayClaim() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withArrayClaim("arrayKey", "arrayValue1", "arrayValue2")
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", 999)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", 999L)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", true)
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testImplicitJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("issuer")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(algorithm);
        JWT verifier = verification.createVerifierForImplicit(asList("issuer"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    private static void verifyClaims(Map<String,Claim> claims) {
        assertTrue(claims.get(Claims.ISSUER).asString().equals("issuer"));
        assertTrue(claims.get(Claims.SUBJECT).asString().equals("subject"));
        assertTrue(claims.get(Claims.AUDIENCE).asString().equals("audience"));
    }
}