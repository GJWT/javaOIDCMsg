package com.auth0.jwt.creators;

import static com.auth0.jwt.creators.GoogleJwtCreatorTest.*;
import static com.auth0.jwt.TimeUtil.generateRandomExpDateInFuture;
import static com.auth0.jwt.TimeUtil.generateRandomIatDateInPast;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.jwts.ExtendedJWT;
import com.auth0.jwt.jwts.JWT;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class ExtendedJwtCreatorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private static final Date exp = generateRandomExpDateInFuture();
    private static final Date iat = generateRandomIatDateInPast();
    private static final Date nbf = iat;

    @Test
    public void testExtendedJwtCreatorAllStandardClaimsMustBeRequired() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorInvalidIssuer() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'iss' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("invalid")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorInvalidPicture() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'picture' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture("invalid")
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorInvalidEmail() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'email' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture(PICTURE)
                .withEmail("invalid")
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorInvalidAudience() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'aud' value doesn't contain the required audience.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("invalid")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorInvalidName() throws Exception {
        thrown.expect(InvalidClaimException.class);
        thrown.expectMessage("The Claim 'name' value doesn't match the required one.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)  //this must be called first since ExtendedJwtCreator.build() returns an instance of ExtendedJwtCreator
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName("invalid")
                .sign(algorithm);
        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorNoneAlgorithmNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNoneAlgorithmNotSpecifiedButStillNotAllowed() throws Exception {
        thrown.expect(IllegalAccessException.class);
        thrown.expectMessage("None algorithm isn't allowed");

        Algorithm algorithm = Algorithm.none();
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .setIsNoneAlgorithmAllowed(false)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNoneAlgorithmAllowed() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .setIsNoneAlgorithmAllowed(true)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        verifyClaims(claims, exp);
    }

    @Test
    public void testExtendedJwtCreatorNonStandardClaimStringValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue")
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNonStandardClaimIntegerValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", 999)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNonStandardClaimLongValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", 999L)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNonStandardClaimDoubleValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", 9.99)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNonStandardClaimBooleanValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", true)
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorNonStandardClaimDateValue() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(exp)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

    @Test
    public void testExtendedJwtCreatorExpTimeHasPassed() throws Exception {
        thrown.expect(TokenExpiredException.class);
        thrown.expectMessage("The Token has expired on Wed Oct 29 00:00:00 PDT 2014.");

        String myDate = "2014/10/29";
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
        Date date = sdf.parse(myDate);
        long expLong = date.getTime();
        Date expDate = new Date(expLong);

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ExtendedJwtCreator.build()
                .withNbf(nbf)
                .withPicture(PICTURE)
                .withEmail(EMAIL)
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withExp(expDate)
                .withIat(iat)
                .withName(NAME)
                .withNonStandardClaim("nonStandardClaim", new Date())
                .sign(algorithm);

        GoogleVerification verification = ExtendedJWT.require(algorithm);
        JWT verifier = verification.createVerifierForExtended(PICTURE, EMAIL, asList("accounts.fake.com"), asList("audience"),
                NAME, 1, 1, 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }
}
