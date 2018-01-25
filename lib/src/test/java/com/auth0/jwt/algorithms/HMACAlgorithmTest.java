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

package com.auth0.jwt.algorithms;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isA;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.auth0.jwt.creators.EncodeType;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.jwts.JWT;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMACAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    // Verify

    @Test
    public void shouldGetStringBytes() throws Exception {
        String text = "abcdef123456!@#$%^";
        byte[] expectedBytes = text.getBytes("UTF-8");
        assertTrue(Arrays.equals(expectedBytes, HMACAlgorithm.getSecretBytes(text)));
    }

    @Test
    public void shouldPassHMAC256Verification() throws Exception {
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithmString = Algorithm.HMAC256(Constants.SECRET);
        Algorithm algorithmBytes = Algorithm.HMAC256(Constants.SECRET.getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(algorithmString).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithmString.verify(decoded, EncodeType.Base64);
        algorithmBytes.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldFailHMAC256VerificationWithInvalidSecretString() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithm = Algorithm.HMAC256("not_real_secret");
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldFailHMAC256VerificationWithInvalidSecretBytes() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA256");
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        Algorithm algorithm = Algorithm.HMAC256("not_real_secret".getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldPassHMAC384Verification() throws Exception {
        String token = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithmString = Algorithm.HMAC384(Constants.SECRET);
        Algorithm algorithmBytes = Algorithm.HMAC384(Constants.SECRET.getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(algorithmString).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithmString.verify(decoded, EncodeType.Base64);
        algorithmBytes.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldFailHMAC384VerificationWithInvalidSecretString() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384");
        String token = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithm = Algorithm.HMAC384("not_real_secret");
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldFailHMAC384VerificationWithInvalidSecretBytes() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA384");
        String token = "eyJhbGciOiJIUzM4NCIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.uztpK_wUMYJhrRv8SV-1LU4aPnwl-EM1q-wJnqgyb5DHoDteP6lN_gE1xnZJH5vw";
        Algorithm algorithm = Algorithm.HMAC384("not_real_secret".getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldPassHMAC512Verification() throws Exception {
        String token = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithmString = Algorithm.HMAC512(Constants.SECRET);
        Algorithm algorithmBytes = Algorithm.HMAC512(Constants.SECRET.getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(algorithmString).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithmString.verify(decoded, EncodeType.Base64);
        algorithmBytes.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldFailHMAC512VerificationWithInvalidSecretString() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512");
        String token = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithm = Algorithm.HMAC512("not_real_secret");
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldFailHMAC512VerificationWithInvalidSecretBytes() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: HmacSHA512");
        String token = "eyJhbGciOiJIUzUxMiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.VUo2Z9SWDV-XcOc_Hr6Lff3vl7L9e5Vb8ThXpmGDFjHxe3Dr1ZBmUChYF-xVA7cAdX1P_D4ZCUcsv3IefpVaJw";
        Algorithm algorithm = Algorithm.HMAC512("not_real_secret".getBytes(StandardCharsets.UTF_8));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }


    @Test
    public void shouldThrowOnVerifyWhenTheSecretIsInvalid() throws Exception {
        exception.expect(AlgorithmMismatchException.class);
        exception.expectMessage("The provided Algorithm doesn't match the one defined in the JWT's Header.");

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.verifySignatureFor(anyString(), any(byte[].class), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", Constants.SECRET.getBytes(StandardCharsets.UTF_8));
        String token = "eyJhbGciOiJIUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJhdXRoMCJ9.mZ0m_N1J4PgeqWmi903JuUoDRZDBPB7HwkS4nVyWH1M";
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    // Sign

    private static final String HS256Header = "eyJhbGciOiJIUzI1NiJ9";
    private static final String HS384Header = "eyJhbGciOiJIUzM4NCJ9";
    private static final String HS512Header = "eyJhbGciOiJIUzUxMiJ9";
    private static final String auth0IssPayload = "eyJpc3MiOiJhdXRoMCJ9";

    @Test
    public void shouldDoHMAC256SigningWithBytes() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET.getBytes(StandardCharsets.UTF_8));

        String jwtContent = String.format("%s.%s", HS256Header, auth0IssPayload);
        byte[] contentBytes = jwtContent.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
        String token = String.format("%s.%s", jwtContent, jwtSignature);
        String expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(jwtSignature, is(expectedSignature));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldDoHMAC384SigningWithBytes() throws Exception {
        Algorithm algorithm = Algorithm.HMAC384(Constants.SECRET.getBytes(StandardCharsets.UTF_8));

        String jwtContent = String.format("%s.%s", HS384Header, auth0IssPayload);
        byte[] contentBytes = jwtContent.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
        String token = String.format("%s.%s", jwtContent, jwtSignature);
        String expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(jwtSignature, is(expectedSignature));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldDoHMAC512SigningWithBytes() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512(Constants.SECRET.getBytes(StandardCharsets.UTF_8));

        String jwtContent = String.format("%s.%s", HS512Header, auth0IssPayload);
        byte[] contentBytes = jwtContent.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
        String token = String.format("%s.%s", jwtContent, jwtSignature);
        String expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(jwtSignature, is(expectedSignature));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldDoHMAC256SigningWithString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256(Constants.SECRET);

        String jwtContent = String.format("%s.%s", HS256Header, auth0IssPayload);
        byte[] contentBytes = jwtContent.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
        String token = String.format("%s.%s", jwtContent, jwtSignature);
        String expectedSignature = "s69x7Mmu4JqwmdxiK6sesALO7tcedbFsKEEITUxw9ho";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(jwtSignature, is(expectedSignature));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldDoHMAC384SigningWithString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC384(Constants.SECRET);

        String jwtContent = String.format("%s.%s", HS384Header, auth0IssPayload);
        byte[] contentBytes = jwtContent.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
        String token = String.format("%s.%s", jwtContent, jwtSignature);
        String expectedSignature = "4-y2Gxz_foN0jAOFimmBPF7DWxf4AsjM20zxNkHg8Zah5Q64G42P9GfjmUp4Hldt";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(jwtSignature, is(expectedSignature));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldDoHMAC512SigningWithString() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512(Constants.SECRET);

        String jwtContent = String.format("%s.%s", HS512Header, auth0IssPayload);
        byte[] contentBytes = jwtContent.getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = algorithm.sign(contentBytes);
        String jwtSignature = Base64.encodeBase64URLSafeString(signatureBytes);
        String token = String.format("%s.%s", jwtContent, jwtSignature);
        String expectedSignature = "OXWyxmf-VcVo8viOiTFfLaEy6mrQqLEos5R82Xsx8mtFxQadJAQ1aVniIWN8qT2GNE_pMQPcdzk4x7Cqxsp1dw";

        assertThat(signatureBytes, is(notNullValue()));
        assertThat(jwtSignature, is(expectedSignature));
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded, EncodeType.Base64);
    }

    @Test
    public void shouldThrowOnSignWhenSignatureAlgorithmDoesNotExists() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(NoSuchAlgorithmException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(byte[].class), any(byte[].class)))
                .thenThrow(NoSuchAlgorithmException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", Constants.SECRET.getBytes(StandardCharsets.UTF_8));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldThrowOnSignWhenTheSecretIsInvalid() throws Exception {
        exception.expect(SignatureGenerationException.class);
        exception.expectMessage("The Token's Signature couldn't be generated when signing using the Algorithm: some-algorithm");
        exception.expectCause(isA(InvalidKeyException.class));

        CryptoHelper crypto = mock(CryptoHelper.class);
        when(crypto.createSignatureFor(anyString(), any(byte[].class), any(byte[].class)))
                .thenThrow(InvalidKeyException.class);

        Algorithm algorithm = new HMACAlgorithm(crypto, "some-alg", "some-algorithm", Constants.SECRET.getBytes(StandardCharsets.UTF_8));
        algorithm.sign(new byte[0]);
    }

    @Test
    public void shouldReturnNullSigningKeyId() throws Exception {
        assertThat(Algorithm.HMAC256(Constants.SECRET).getSigningKeyId(), is(nullValue()));
    }

}