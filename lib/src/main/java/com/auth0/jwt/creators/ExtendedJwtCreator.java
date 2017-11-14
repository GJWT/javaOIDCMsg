package com.auth0.jwt.creators;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.util.Date;

/**
 * The ExtendedJwtCreator class holds the sign method to generate a complete Extended JWT (with Signature) from a given Header and Payload content.
 */
public class ExtendedJwtCreator extends GoogleJwtCreator{

    public ExtendedJwtCreator() {
        super();
    }

    /**
     * Add a specific Note Before ("nbf") claim to the Payload.
     *
     * @param nbf the nbf value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withNbf(Date nbf) {
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
        if(!jwt.getIsNoneAlgorithmAllowed() && algorithm.equals(Algorithm.none())) {
            throw new IllegalAccessException("None algorithm isn't allowed");
        }
        String JWS = jwt.sign(algorithm);
        verifyClaims();
        return JWS;
    }

    /**
     * Verifies that all the standard claims were provided
     * @throws Exception if all the standard claims weren't provided
     */
    private void verifyClaims() throws Exception {
        for(String claim : addedClaims.keySet())
            if(!addedClaims.get(claim))
                throw new Exception("Standard claim: " + claim + " has not been set");
    }

    public static ExtendedJwtCreator build() {
        return new ExtendedJwtCreator();
    }
}
