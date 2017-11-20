package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.jwts.JWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class NoneAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldPassNoneVerification() throws Exception {
        Algorithm algorithm = Algorithm.none();
        String token = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded);
    }

    @Test
    public void shouldFailNoneVerificationWhenTokenHasTwoParts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        String token = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9";
        Algorithm algorithm = Algorithm.none();
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded);
    }

    @Test
    public void shouldFailNoneVerificationWhenSignatureIsPresent() throws Exception {
        exception.expect(SignatureVerificationException.class);
        exception.expectMessage("The Token's Signature resulted invalid when verified using the Algorithm: none");
        String token = "eyJhbGciOiJub25lIiwiY3R5IjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.Ox-WRXRaGAuWt2KfPvWiGcCrPqZtbp_4OnQzZXaTfss";
        Algorithm algorithm = Algorithm.none();
        JWT jwt = JWT.require(algorithm).withIssuer("auth0").build();
        DecodedJWT decoded = jwt.decode(token);
        algorithm.verify(decoded);
    }

    @Test
    public void shouldReturnNullSigningKeyId() throws Exception {
        assertThat(Algorithm.none().getSigningKeyId(), is(nullValue()));
    }

}