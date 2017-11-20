package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.jwts.JWT;
import org.apache.commons.codec.binary.Base64;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsCollectionContaining;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class JWTDecoderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void getSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).withNonStandardClaim("admin", true).withNonStandardClaim("name", "John Doe").build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT.getSubject(), is(notNullValue()));
        assertTrue(decodedJWT.getSubject().contains("1234567890"));
    }

    // Exceptions
    @Test
    public void shouldThrowIfLessThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).withNonStandardClaim("admin", true).withNonStandardClaim("name", "John Doe").build();
        DecodedJWT decodedJWT = jwt.decode("two.parts");
    }

    @Test
    public void shouldThrowIfMoreThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).withNonStandardClaim("admin", true).withNonStandardClaim("name", "John Doe").build();
        DecodedJWT decodedJWT = jwt.decode("this.has.four.parts");
    }

    @Test
    public void shouldThrowIfPayloadHasInvalidJSONFormat() throws Exception {
        String validJson = "{}";
        String invalidJson = "}{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", invalidJson));
        customJWT(validJson, invalidJson, "signature");
    }

    @Test
    public void shouldThrowIfHeaderHasInvalidJSONFormat() throws Exception {
        String validJson = "{}";
        String invalidJson = "}{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", invalidJson));
        customJWT(invalidJson, validJson, "signature");
    }

    // Parts

    @Test
    public void shouldGetStringToken() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getToken(), is(notNullValue()));
        assertThat(decodedJWT.getToken(), is("eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    @Test
    public void shouldGetHeader() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getHeader(), is("eyJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void shouldGetPayload() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getPayload(), is("e30"));
    }

    @Test
    public void shouldGetSignature() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getSignature(), is("XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"));
    }

    // Public PublicClaims

    @Test
    public void shouldGetIssuer() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJKb2huIERvZSJ9.SgXosfRR_IwCgHq5lF3tlM-JHtpucWCRSaVuoHTbWbQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertTrue(decodedJWT.getIssuer().contains("John Doe"));
    }

    @Test
    public void shouldGetSubject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUb2szbnMifQ.RudAxkslimoOY3BLl2Ghny3BrUKu9I1ZrXzCZGDJtNs";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertTrue(decodedJWT.getSubject().contains("Tok3ns"));
    }

    @Test
    public void shouldGetArrayAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiSG9wZSIsIlRyYXZpcyIsIlNvbG9tb24iXX0.Tm4W8WnfPjlmHSmKFakdij0on2rWPETpoM7Sh0u6-S4";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getAudience(), is(IsCollectionWithSize.hasSize(3)));
        assertThat(decodedJWT.getAudience(), is(IsCollectionContaining.hasItems("Hope", "Travis", "Solomon")));
    }

    @Test
    public void shouldGetStringAudience() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJKYWNrIFJleWVzIn0.a4I9BBhPt1OB1GW67g2P1bEHgi6zgOjGUL4LvhE9Dgc";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getAudience(), is(IsCollectionWithSize.hasSize(1)));
        assertThat(decodedJWT.getAudience(), is(IsCollectionContaining.hasItems("Jack Reyes")));
    }

    @Test
    public void shouldGetExpirationTime() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE0NzY3MjcwODZ9.L9dcPHEDQew2u9MkDCORFkfDGcSOsgoPqNY-LUMLEHg";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).acceptExpiresAt(1476727086).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getExpiresAt(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(decodedJWT.getExpiresAt(), is(notNullValue()));
        assertThat(decodedJWT.getExpiresAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetNotBefore() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYmYiOjE0NzY3MjcwODZ9.tkpD3iCPQPVqjnjpDVp2bJMBAgpVCG9ZjlBuMitass0";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).acceptNotBefore(1476727086).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getNotBefore(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(decodedJWT.getNotBefore(), is(notNullValue()));
        assertThat(decodedJWT.getNotBefore(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetIssuedAt() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NzY3MjcwODZ9.KPjGoW665E8V5_27Jugab8qSTxLk2cgquhPCBfAP0_w";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).acceptIssuedAt(1476727086).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getIssuedAt(), is(instanceOf(Date.class)));
        long ms = 1476727086L * 1000;
        Date expectedDate = new Date(ms);
        assertThat(decodedJWT.getIssuedAt(), is(notNullValue()));
        assertThat(decodedJWT.getIssuedAt(), is(equalTo(expectedDate)));
    }

    @Test
    public void shouldGetId() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIxMjM0NTY3ODkwIn0.m3zgEfVUFOd-CvL3xG5BuOWLzb0zMQZCqiVNQQOPOvA";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getId(), is("1234567890"));
    }

    @Test
    public void shouldGetContentType() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6ImF3ZXNvbWUifQ.e30.AIm-pJDOaAyct9qKMlN-lQieqNDqc3d4erqUZc5SHAs";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getContentType(), is("awesome"));
    }

    @Test
    public void shouldGetType() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.e30.WdFmrzx8b9v_a-r6EHC2PTAaWywgm_8LiP8RBRhYwkI";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getType(), is("JWS"));
    }

    @Test
    public void shouldGetAlgorithm() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getAlgorithm(), is("HS256"));
    }

    //Private PublicClaims


    @Test
    public void shouldGetValidClaim() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnsibmFtZSI6ImpvaG4ifX0.lrU1gZlOdlmTTeZwq0VI-pZx2iV46UWYd5-lCjy6-c4";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getClaim("object"), is(notNullValue()));
        assertThat(decodedJWT.getClaim("object"), is(instanceOf(Claim.class)));
    }


    @Test
    public void shouldNotGetNullClaimIfClaimIsEmptyObject() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJvYmplY3QiOnt9fQ.d3nUeeL_69QsrHL0ZWij612LHEQxD8EZg1rNoY3a4aI";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        assertThat(decodedJWT.getClaim("object"), is(notNullValue()));
        assertThat(decodedJWT.getClaim("object").isNull(), is(false));
    }

    @Test
    public void shouldGetCustomClaimOfTypeInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxMjN9.XZAudnA7h3_Al5kJydzLjw6RzZC3Q6OvnLEYlhNW7HA";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Assert.assertThat(decodedJWT.getClaim("name").asInt(), is(123));
    }

    @Test
    public void shouldGetCustomClaimOfTypeDouble() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoyMy40NX0.7pyX2OmEGaU9q15T8bGFqRm-d3RVTYnqmZNZtxMKSlA";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Assert.assertThat(decodedJWT.getClaim("name").asDouble(), is(23.45));
    }

    @Test
    public void shouldGetCustomClaimOfTypeBoolean() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjp0cnVlfQ.FwQ8VfsZNRqBa9PXMinSIQplfLU4-rkCLfIlTLg_MV0";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Assert.assertThat(decodedJWT.getClaim("name").asBoolean(), is(true));
    }

    @Test
    public void shouldGetCustomClaimOfTypeDate() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoxNDc4ODkxNTIxfQ.mhioumeok8fghQEhTKF3QtQAksSvZ_9wIhJmgZLhJ6c";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Date date = new Date(1478891521000L);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Assert.assertThat(decodedJWT.getClaim("name").asDate().getTime(), is(date.getTime()));
    }

    @Test
    public void shouldGetCustomArrayClaimOfTypeString() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19.lxM8EcmK1uSZRAPd0HUhXGZJdauRmZmLjoeqz4J9yAA";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Assert.assertThat(decodedJWT.getClaim("name").asArray(String.class), arrayContaining("text", "123", "true"));
    }

    @Test
    public void shouldGetCustomArrayClaimOfTypeInteger() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjpbMSwyLDNdfQ.UEuMKRQYrzKAiPpPLhIVawWkKWA1zj0_GderrWUIyFE";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Assert.assertThat(decodedJWT.getClaim("name").asArray(Integer.class), arrayContaining(1, 2, 3));
    }

    @Test
    public void shouldGetCustomMapClaim() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjp7InN0cmluZyI6InZhbHVlIiwibnVtYmVyIjoxLCJib29sZWFuIjp0cnVlfX0.-8aIaXd2-rp1lLuDEQmCeisCBX9X_zbqdPn2llGxNoc";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        Assert.assertThat(decodedJWT, is(notNullValue()));
        Map<String, Object> map = decodedJWT.getClaim("name").asMap();
        Assert.assertThat(map, hasEntry("string", (Object) "value"));
        Assert.assertThat(map, hasEntry("number", (Object) 1));
        Assert.assertThat(map, hasEntry("boolean", (Object) true));
    }

    @Test
    public void shouldGetAvailableClaims() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjM0NTY3ODkwIiwiaWF0IjoiMTIzNDU2Nzg5MCIsIm5iZiI6IjEyMzQ1Njc4OTAiLCJqdGkiOiJodHRwczovL2p3dC5pby8iLCJhdWQiOiJodHRwczovL2RvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJsb2dpbiIsImlzcyI6ImF1dGgwIiwiZXh0cmFDbGFpbSI6IkpvaG4gRG9lIn0.TX9Ct4feGp9YyeGK9Zl91tO0YBOrguJ4As9jeqgHdZQ";
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(token);
        assertThat(decodedJWT, is(notNullValue()));
        Map<String,Claim> claims = decodedJWT.getClaims();
        assertThat(claims, is(notNullValue()));
        assertThat(claims, is(instanceOf(Map.class)));
        assertThat(claims.get("exp"), is(notNullValue()));
        assertThat(claims.get("iat"), is(notNullValue()));
        assertThat(claims.get("nbf"), is(notNullValue()));
        assertThat(claims.get("jti"), is(notNullValue()));
        assertThat(claims.get("aud"), is(notNullValue()));
        assertThat(claims.get("sub"), is(notNullValue()));
        assertThat(claims.get("iss"), is(notNullValue()));
        assertThat(claims.get("extraClaim"), is(notNullValue()));
    }

    //Helper Methods

    private DecodedJWT customJWT(String jsonHeader, String jsonPayload, String signature) throws Exception{
        String header = Base64.encodeBase64URLSafeString(jsonHeader.getBytes(StandardCharsets.UTF_8));
        String body = Base64.encodeBase64URLSafeString(jsonPayload.getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(Algorithm.HMAC256("secret")).build();
        DecodedJWT decodedJWT = jwt.decode(String.format("%s.%s.%s", header, body, signature));
        return decodedJWT;
    }
}