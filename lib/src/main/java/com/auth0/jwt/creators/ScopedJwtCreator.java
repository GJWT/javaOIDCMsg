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

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.impl.Claims;
import com.auth0.jwt.jwts.JWT;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * The ScopedJwtCreator class holds the sign method to generate a complete Scoped JWT (with Signature) from a given Header and Payload content.
 */
public class ScopedJwtCreator {

    protected JWTCreator.Builder jwt;
    protected HashMap<String, Boolean> requiredClaims;

    private ScopedJwtCreator() {
        jwt = JWT.create();
        requiredClaims = new HashMap<String, Boolean>() {{
            put(Claims.SCOPE, false);
            put(Claims.ISSUER, false);
            put(Claims.SUBJECT, false);
            put(Claims.ISSUED_AT, false);
        }};
    }

    /**
     * Add a specific Scope (Claims.SCOPE) claim to the Payload.
     * Allows for multiple issuers
     *
     * @param scope the Scope value.
     * @return this same Builder instance.
     */
    public ScopedJwtCreator withScope(String scope) {
        jwt.withNonStandardClaim(Claims.SCOPE, scope);
        requiredClaims.put(Claims.SCOPE, true);
        return this;
    }

    /**
     * Add a specific Issuer (Claims.ISSUER) claim to the Payload.
     *
     * @param issuer the Issuer value.
     * @return this same Builder instance.
     */
    public ScopedJwtCreator withIssuer(String issuer) {
        jwt.withIssuer(issuer);
        requiredClaims.put(Claims.ISSUER, true);
        return this;
    }

    /**
     * Add a specific Subject (Claims.SUBJECT) claim to the Payload.
     *
     * @param subject the Subject value.
     * @return this same Builder instance.
     */
    public ScopedJwtCreator withSubject(String subject) {
        jwt.withSubject(subject);
        requiredClaims.put(Claims.SUBJECT, true);
        return this;
    }

    /**
     * Add a specific Audience ("audience") claim to the Payload.
     * Allows for multiple audience
     *
     * @param audience the Audience value.
     * @return this same Builder instance.
     */
    public ScopedJwtCreator withAudience(String... audience) {
        jwt.withAudience(audience);
        return this;
    }

    /**
     * Add a specific Issued At (Claims.ISSUED_AT) claim to the Payload.
     *
     * @param iat the Issued At value.
     * @return this same Builder instance.
     */
    public ScopedJwtCreator withIat(Date iat) {
        jwt.withIssuedAt(iat);
        requiredClaims.put(Claims.ISSUED_AT, true);
        return this;
    }

    /**
     * Add a specific Expires At ("exp") claim to the Payload.
     *
     * @param exp the Expires At value.
     * @return this same Builder instance.
     */
    public ScopedJwtCreator withExp(Date exp) {
        jwt.withExpiresAt(exp);
        return this;
    }

    /**
     * Require a specific Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withNonStandardClaim(String name, String value) {
        if(name.equalsIgnoreCase("subject") || name.equalsIgnoreCase(Claims.SUBJECT)) {
            withSubject(value);
        } else if(name.equalsIgnoreCase("issuer") || name.equalsIgnoreCase(Claims.ISSUER)) {
            withIssuer(value);
        } else if(name.equalsIgnoreCase(Claims.SCOPE)) {
            withScope(value);
        } else {
            jwt.withNonStandardClaim(name, value);
        }
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
        jwt.withNonStandardClaim(name, value);
        return this;
    }

    /**
     * Add a custom Claim value.
     *
     * @param name  the Claim's name.
     * @param value the Claim's value.
     * @return this same Builder instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
        if(name.equalsIgnoreCase(Claims.ISSUED_AT) || name.equalsIgnoreCase("issuedAt") || name.equalsIgnoreCase("issued_at")) {
            withIat(value);
        } else {
            jwt.withNonStandardClaim(name, value);
        }
        return this;
    }

    /**
     * Require a specific Array Claim to contain at least the given items.
     *
     * @param name  the Claim's name.
     * @param items the items the Claim must contain.
     * @return this same Verification instance.
     * @throws IllegalArgumentException if the name is null.
     */
    public ScopedJwtCreator withArrayClaim(String name, String... items) throws IllegalArgumentException {
        jwt.withArrayClaim(name, items);
        if(requiredClaims.containsKey(name))
            requiredClaims.put(name, true);
        return this;
    }

    /**
     * Developer explicitly specifies whether they want to accept
     * NONE algorithms or not.
     *
     * @param isNoneAlgorithmAllowed
     * @return
     */
    public ScopedJwtCreator setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
        jwt.setIsNoneAlgorithmAllowed(isNoneAlgorithmAllowed);
        return this;
    }

    /**
     * Creates a new JWT and signs it with the given algorithm.
     *
     * @param algorithm used to sign the JWT
     * @return a new JWT token
     * @throws IllegalAccessException   if the developer didn't want NONE algorithm to be allowed and it was passed in
     * @throws IllegalArgumentException if the provided algorithm is null.
     * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
     */
    public String sign(Algorithm algorithm) throws Exception {
        if(!jwt.getIsNoneAlgorithmAllowed() && Algorithm.none().equals(algorithm)) {
            throw new IllegalAccessException("None algorithm isn't allowed");
        }
        verifyClaims();
        String JWS = jwt.sign(algorithm);
        return JWS;
    }

    /**
     * Creates a new JWT and signs it with the given algorithm.
     *
     * @param algorithm used to sign the JWT
     * @return a new JWT token
     * @throws IllegalAccessException   if the developer didn't want NONE algorithm to be allowed and it was passed in
     * @throws IllegalArgumentException if the provided algorithm is null.
     * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
     */
    public String signBase16Encoding(Algorithm algorithm) throws Exception {
        if(!jwt.getIsNoneAlgorithmAllowed() && Algorithm.none().equals(algorithm)) {
            throw new IllegalAccessException("None algorithm isn't allowed");
        }
        verifyClaims();
        String JWS = jwt.sign(algorithm, EncodeType.Base16);
        return JWS;
    }

    /**
     * Creates a new JWT and signs it with the given algorithm.
     *
     * @param algorithm used to sign the JWT
     * @return a new JWT token
     * @throws IllegalAccessException   if the developer didn't want NONE algorithm to be allowed and it was passed in
     * @throws IllegalArgumentException if the provided algorithm is null.
     * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
     */
    public String signBase32Encoding(Algorithm algorithm) throws Exception {
        if(!jwt.getIsNoneAlgorithmAllowed() && Algorithm.none().equals(algorithm)) {
            throw new IllegalAccessException("None algorithm isn't allowed");
        }
        verifyClaims();
        String JWS = jwt.sign(algorithm, EncodeType.Base32);
        return JWS;
    }

    /**
     * Verifies that all the standard claims were provided
     * @throws Exception if all the standard claims weren't provided
     */
    private void verifyClaims() throws Exception {
        for(String claim : requiredClaims.keySet())
            if(!requiredClaims.get(claim))
                throw new Exception("Standard claim: " + claim + " has not been set");
    }

    public static ScopedJwtCreator build() {
        return new ScopedJwtCreator();
    }
}
