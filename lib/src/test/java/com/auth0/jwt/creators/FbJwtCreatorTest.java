package com.auth0.jwt.creators;

import static com.auth0.jwt.TimeUtil.generateRandomExpDateInFuture;
import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.creators.FbJwtCreator;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.jwts.FbJWT;
import com.auth0.jwt.jwts.JWT;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.text.SimpleDateFormat;
import java.util.*;

public class FbJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();
    private static final String USER_ID = "userId";
    private static final String APP_ID = "appId";

    @Test
    public void testFbJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorInvalidUserId() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'userId' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId("invalid")
                .withAppId(APP_ID)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testFbJwtCreatorInvalidAppId() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'appId' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId("invalid")
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testFbJwtCreatorUserIdNotProvided() throws Exception {
        thrown.expect(Exception.class);
        thrown.expectMessage("Standard claim: UserId has not been set");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withAppId(APP_ID)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testFbJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testFbJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testFbJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorArrayClaim() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withArrayClaim("arrayKey", "arrayValue1", "arrayValue2")
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", 999)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", 999L)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", true)
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }

    @Test
    public void testFbJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(exp)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }
    @Test
    public void testFbJwtCreatorExpTimeHasPassed() throws Exception {
        thrown.expect(TokenExpiredException.class);
        thrown.expectMessage("The Token has expired on Wed Oct 29 00:00:00 PDT 2014.");

        String myDate = "2014/10/29";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date date = sdf.parse(myDate);
        long expLong = date.getTime();
        Date expDate = new Date(expLong);

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = FbJwtCreator.build()
                .withExp(expDate)
                .withIat(iat)
                .withUserId(USER_ID)
                .withAppId(APP_ID)
                .setIsNoneAlgorithmAllowed(true)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);
        Verification verification = FbJWT.require(algorithm);
        JWT verifier = verification.createVerifierForFb(USER_ID, APP_ID).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims);
    }


    private static void verifyClaims(Map<String,Claim> claims) {
        assertTrue(claims.get(USER_ID).asString().equals(USER_ID));
        assertTrue(claims.get(APP_ID).asString().equals(APP_ID));
        assertTrue(claims.get(PublicClaims.EXPIRES_AT).asDate().toString().equals(exp.toString()));
    }
}