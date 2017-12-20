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

import com.auth0.jwt.JsonMatcher;
import com.auth0.jwt.PemUtils;
import com.auth0.jwt.TokenUtils;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.auth0.jwt.jwts.JWT;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class JWTCreatorTest {

    private static final String PRIVATE_KEY_FILE_RSA = "src/test/resources/rsa-private-base16-64.pem";
    private static final String PRIVATE_KEY_FILE_EC_256 = "src/test/resources/ec256-key-private.pem";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldThrowWhenRequestingSignWithoutAlgorithm() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Algorithm cannot be null");
        JWTCreator.init()
                .sign(null);
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldAddHeaderClaim() throws Exception {
        Map<String, Object> header = new HashMap<String, Object>();
        header.put("asd", 123);
        String signed = JWTCreator.init()
                .withHeader(header)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("asd", 123));
    }

    @Test
    public void shouldAddKeyId() throws Exception {
        String signed = JWTCreator.init()
                .withKeyId("56a8bd44da435300010000015f5ed")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "56a8bd44da435300010000015f5ed"));
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromRSAAlgorithms() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .sign(Algorithm.RSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI"));
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromRSAAlgorithmsForBase16() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);
        Algorithm algorithm = Algorithm.RSA256(provider);

        String signed = JWTCreator.init()
                .withKeyId("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI")
                .withIssuer("auth0")
                .sign(algorithm, EncodeType.Base16);

        JWT jwt = JWT.require(Algorithm.RSA256(provider)).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode16BytesWithX509(signed,"./jwksRSA.json", "./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
        algorithm.verifyWithX509(decoded, EncodeType.Base16,"./jwksRSA.json", "./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromRSAAlgorithmsForBase32() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);
        Algorithm algorithm = Algorithm.RSA256(provider);

        String signed = JWTCreator.init()
                .withKeyId("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI")
                .withIssuer("auth0")
                .sign(algorithm, EncodeType.Base32);

        JWT jwt = JWT.require(Algorithm.RSA256(provider)).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode32BytesWithX509(signed, "./jwksRSA.json", "./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
        algorithm.verifyWithX509(decoded, EncodeType.Base32,"./jwksRSA.json", "./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromRSAAlgorithmsForBase64() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);
        Algorithm algorithm = Algorithm.RSA256(provider);

        String signed =
                JWTCreator.init()
                        .withKeyId("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI")
                        .withIssuer("https://agaton-sax.com/")
                        .withNonStandardClaim("foo","bar")
                        .withNonStandardClaim("kit", "kat")
                        .sign(algorithm, EncodeType.Base64);

        JWT jwt = JWT.require(Algorithm.RSA256(provider)).withIssuer("https://agaton-sax.com/")
                .withNonStandardClaim("foo","bar")
                .withNonStandardClaim("kit", "kat").build();
        DecodedJWT decoded = jwt.decodeWithX509(signed, "./jwksRSA.json", "./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
        algorithm.verifyWithX509(decoded, EncodeType.Base64, "./jwksRSA.json", "./src/main/java/com/auth0/jwt/algorithms/jwks.pem");
    }


    @Test
    public void shouldNotOverwriteKeyIdIfAddedFromRSAAlgorithms() throws Exception {
        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_RSA, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .withKeyId("real-key-id")
                .sign(Algorithm.RSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI"));
    }

    @Test
    public void shouldAddKeyIdIfAvailableFromECDSAAlgorithms() throws Exception {
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC");
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .sign(Algorithm.ECDSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI"));
    }

    @Test
    public void shouldNotOverwriteKeyIdIfAddedFromECDSAAlgorithms() throws Exception {
        ECPrivateKey privateKey = (ECPrivateKey) PemUtils.readPrivateKeyFromFile(PRIVATE_KEY_FILE_EC_256, "EC");
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI");
        when(provider.getPrivateKey()).thenReturn(privateKey);

        String signed = JWTCreator.init()
                .withKeyId("real-key-id")
                .sign(Algorithm.ECDSA256(provider));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("kid", "8RGoVdVjD8fItyR3FFo0hVNaZYtPGwoP6xKi9e_V7bI"));
    }

    @Test
    public void shouldAddIssuer() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("auth0")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpc3MiOlsiYXV0aDAiXX0"));
    }

    @Test
    public void shouldAddSubject() throws Exception {
        String signed = JWTCreator.init()
                .withSubject("1234567890")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJzdWIiOlsiMTIzNDU2Nzg5MCJdfQ"));
    }

    @Test
    public void shouldAddAudience() throws Exception {
        String signed = JWTCreator.init()
                .withAudience("Mark")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJhdWQiOiJNYXJrIn0"));


        String signedArr = JWTCreator.init()
                .withAudience("Mark", "David")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signedArr, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signedArr)[1], is("eyJhdWQiOlsiTWFyayIsIkRhdmlkIl19"));
    }

    @Test
    public void shouldAddExpiresAt() throws Exception {
        String signed = JWTCreator.init()
                .withExpiresAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJleHAiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddNotBefore() throws Exception {
        String signed = JWTCreator.init()
                .withNotBefore(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJuYmYiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddIssuedAt() throws Exception {
        String signed = JWTCreator.init()
                .withIssuedAt(new Date(1477592000))
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJpYXQiOjE0Nzc1OTJ9"));
    }

    @Test
    public void shouldAddJWTId() throws Exception {
        String signed = JWTCreator.init()
                .withJWTId("jwt_id_123")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("eyJqdGkiOiJqd3RfaWRfMTIzIn0"));
    }

    @Test
    public void shouldRemoveClaimWhenPassingNull() throws Exception {
        String signed = JWTCreator.init()
                .withIssuer("iss")
                .withIssuer(null)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[1], is("e30"));
    }

    @Test
    public void shouldSetCorrectAlgorithmInTheHeader() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("alg", "HS256"));
    }

    @Test
    public void shouldSetCorrectTypeInTheHeader() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.HMAC256("secret"));

        assertThat(signed, is(notNullValue()));
        String[] parts = signed.split("\\.");
        String headerJson = new String(Base64.decodeBase64(parts[0]), StandardCharsets.UTF_8);
        assertThat(headerJson, JsonMatcher.hasEntry("typ", "JWT"));
    }

    @Test
    public void shouldSetEmptySignatureIfAlgorithmIsNone() throws Exception {
        String signed = JWTCreator.init()
                .sign(Algorithm.none());
        assertThat(signed, is(notNullValue()));
        assertThat(TokenUtils.splitToken(signed)[2], is(""));
    }

    @Test
    public void shouldThrowOnNullCustomClaimName() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Custom Claim's name can't be null.");
        JWTCreator.init()
                .withNonStandardClaim(null, "value");
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeString() throws Exception {
        String jwt = JWTCreator.init()
                .withNonStandardClaim("name", "value")
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoidmFsdWUifQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeInteger() throws Exception {
        String jwt = JWTCreator.init()
                .withNonStandardClaim("name", 123)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxMjN9"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeLong() throws Exception {
        String jwt = JWTCreator.init()
                .withNonStandardClaim("name", Long.MAX_VALUE)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjo5MjIzMzcyMDM2ODU0Nzc1ODA3fQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDouble() throws Exception {
        String jwt = JWTCreator.init()
                .withNonStandardClaim("name", 23.45)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoyMy40NX0"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeBoolean() throws Exception {
        String jwt = JWTCreator.init()
                .withNonStandardClaim("name", true)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjp0cnVlfQ"));
    }

    @Test
    public void shouldAcceptCustomClaimOfTypeDate() throws Exception {
        Date date = new Date(1478891521000L);
        String jwt = JWTCreator.init()
                .withNonStandardClaim("name", date)
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjoxNDc4ODkxNTIxfQ"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeString() throws Exception {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new String[]{"text", "123", "true"})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbInRleHQiLCIxMjMiLCJ0cnVlIl19"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeInteger() throws Exception {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new Integer[]{1, 2, 3})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
    }

    @Test
    public void shouldAcceptCustomArrayClaimOfTypeLong() throws Exception {
        String jwt = JWTCreator.init()
                .withArrayClaim("name", new Long[]{1L, 2L, 3L})
                .sign(Algorithm.HMAC256("secret"));

        assertThat(jwt, is(notNullValue()));
        String[] parts = jwt.split("\\.");
        assertThat(parts[1], is("eyJuYW1lIjpbMSwyLDNdfQ"));
    }
}