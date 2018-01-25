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
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.interfaces.constants.Constants;
import com.auth0.jwt.interfaces.constants.PublicClaims;
import com.auth0.jwt.jwts.JWT;
import com.auth0.jwt.jwts.ScopedJWT;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ScopedJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();


    @Test
    public void testScopedJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorBase16Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .signBase16Encoding(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode16Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorBase32Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .signBase32Encoding(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode32Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorInvalidScope() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'scope' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope("invalid")
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testScopedJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer("invalid")
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testScopedJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience("invalid")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testScopedJwtCreatorScopeNotProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Scope has not been set");
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);

        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testScopedJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);

        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testScopedJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .setIsNoneAlgorithmAllowed(true)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorArrayClaim() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withArrayClaim("arrayKey", "arrayValue1", "arrayValue2")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", 999)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", 999L)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", true)
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .withExp(exp)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testScopedJwtCreatorExpTimeHasPassed() throws Exception {
        thrown.expect(TokenExpiredException.class);
        thrown.expectMessage("The Token has expired on Wed Oct 29 00:00:00 PDT 2014.");

        String myDate = "2014/10/29";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date date = sdf.parse(myDate);
        long expLong = date.getTime();
        Date expDate = new Date(expLong);

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = ScopedJwtCreator.build()
                .withScope(Constants.SCOPE)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .withExp(expDate)
                .withIat(iat)
                .sign(algorithm);
        Verification verification = ScopedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForScoped(Constants.SCOPE, asList(Constants.ISSUER), asList(Constants.AUDIENCE), 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, expDate);
    }

    private static void verifyClaims(Map<String, Claim> claims, Date exp) {
        assertTrue(claims.get(PublicClaims.ISSUER).asList(String.class).get(0).equals(Constants.ISSUER));
        assertTrue(claims.get(PublicClaims.SUBJECT).asList(String.class).get(0).equals(Constants.SUBJECT));
        assertTrue(claims.get(PublicClaims.AUDIENCE).asString().equals(Constants.AUDIENCE));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
    }
}