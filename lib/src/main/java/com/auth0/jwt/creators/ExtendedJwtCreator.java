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

import java.util.Date;

/**
 * The ExtendedJwtCreator class holds the sign method to generate a complete Extended JWT (with Signature) from a given Header and Payload content.
 */
public class ExtendedJwtCreator extends GoogleJwtCreator{

    private ExtendedJwtCreator() {
        super();
    }

    /**
     * Add a specific Note Before ("nbf") claim to the Payload.
     *
     * @param nbf the nbf value.
     * @return this same Builder instance.
     */
    public ExtendedJwtCreator withNbf(Date nbf) {
        jwt.withNotBefore(nbf);
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

    public static ExtendedJwtCreator build() {
        return new ExtendedJwtCreator();
    }
}
