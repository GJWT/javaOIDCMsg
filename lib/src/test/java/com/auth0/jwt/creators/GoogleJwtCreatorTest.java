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
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.interfaces.constants.Constants;
import com.auth0.jwt.interfaces.constants.PublicClaims;
import com.auth0.jwt.jwts.GoogleJWT;
import com.auth0.jwt.jwts.JWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class GoogleJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();


    @Test
    public void testGoogleJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorBase16Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .signBase16Encoding(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode16Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorBase32Encoding() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .signBase32Encoding(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode32Bytes(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorWhenCertainRequiredClaimIsntProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: Picture has not been set");

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .setIsNoneAlgorithmAllowed(true)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorArrayClaim() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .setIsNoneAlgorithmAllowed(true)
                .withArrayClaim("arrayKey", "arrayValue1", "arrayValue2")
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.none();
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer("invalid")
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .setIsNoneAlgorithmAllowed(true)
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience("invalid")
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidPicture() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'picture' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture("invalid")
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidEmail() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'email' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail("invalid")
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorInvalidName() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'name' value doesn't match the required one.");

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName("invalid")
                .sign(algorithm);

        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaimString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaimBoolean() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .withNonStandardClaim("nonStandardClaim", true)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaimInteger() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .withNonStandardClaim("nonStandardClaim", 999)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaimLong() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .withNonStandardClaim("nonStandardClaim", 999L)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaimDouble() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorNonStandardClaimDate() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iat)
                .withName(Constants.NAME)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testGoogleJwtCreatorExpTimeHasPassed() throws Exception {
        thrown.expect(TokenExpiredException.class);
        thrown.expectMessage("The Token has expired on Wed Oct 29 00:00:00 PDT 2014.");

        String myDate = "2014/10/29";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date date = sdf.parse(myDate);
        long expLong = date.getTime();
        Date expDate = new Date(expLong);

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(expDate)
                .withIat(iat)
                .withName(Constants.NAME)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testGoogleJwtCreatorTokenCantBeUsedBefore() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Token can't be used before Mon Oct 29 00:00:00 PDT 2018.");

        String myDate = "2018/10/29";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date date = sdf.parse(myDate);
        long expLong = date.getTime();
        Date iatDate = new Date(expLong);

        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);
        String token = GoogleJwtCreator.build()
                .withPicture(Constants.PICTURE)
                .withEmail(Constants.EMAIL)
                .withIssuer(Constants.ISSUER)
                .withSubject(Constants.SUBJECT)
                .withAudience(Constants.AUDIENCE)
                .withExp(exp)
                .withIat(iatDate)
                .withName(Constants.NAME)
                .sign(algorithm);
        GoogleVerification verification = GoogleJWT.require(algorithm);
        JWT verifier = verification.createVerifierForGoogle(Constants.PICTURE, Constants.EMAIL, asList(Constants.ISSUER), asList(Constants.AUDIENCE),
                Constants.NAME, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testCreateVerifierForExtended() throws Exception {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("you shouldn't be calling this method");
        GoogleVerification verification = GoogleJWT.require(Algorithm.HMAC256(Constants.SECRET));
        verification.createVerifierForExtended(null, null, null, null, null, 1L, 1L, 1L);
    }

    protected static void verifyClaims(Map<String, Claim> claims, Date exp) {
        assertTrue(claims.get(Constants.PICTURE).asString().equals(Constants.PICTURE));
        assertTrue(claims.get(Constants.EMAIL).asString().equals(Constants.EMAIL));
        assertTrue(claims.get(PublicClaims.ISSUER).asList(String.class).get(0).equals(Constants.ISSUER));
        assertTrue(claims.get(PublicClaims.SUBJECT).asList(String.class).get(0).equals(Constants.SUBJECT));
        assertTrue(claims.get(PublicClaims.AUDIENCE).asString().equals(Constants.AUDIENCE));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
        assertTrue(claims.get(Constants.NAME).asString().equals(Constants.NAME));
    }
}