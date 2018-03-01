package com.auth0.jwt.creators;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.RequiredClaimException;
import com.auth0.jwt.impl.Claims;
import com.auth0.jwt.jwts.JWT;
import java.util.HashMap;
import java.util.Map;

public abstract class Creator {

    protected JWTCreator.Builder jwt;
    protected Map<String, Boolean> requiredClaimsImplicit;
    protected Map<String, Boolean> requiredClaimsGoogle;
    protected Map<String, Boolean> requiredClaimsAccess;
    protected Map<String, Boolean> requiredClaimsFB;
    protected Map<String, Boolean> requiredClaimsRisc;
    protected Map<String, Boolean> requiredClaimsScoped;

    protected Creator() {
        jwt = JWT.create();
        requiredClaimsImplicit = new HashMap<String, Boolean>() {{
            put(Claims.ISSUER, false);
            put(Claims.SUBJECT, false);
            put(Claims.ISSUED_AT, false);
        }};
        requiredClaimsGoogle = new HashMap<String, Boolean>() {{
            put(Claims.NAME, false);
            put(Claims.EMAIL, false);
            put(Claims.PICTURE, false);
            put(Claims.ISSUER, false);
            put(Claims.SUBJECT, false);
            put(Claims.ISSUED_AT, false);
        }};
        requiredClaimsAccess = new HashMap<String, Boolean>() {{
            put(Claims.ISSUER, false);
            put(Claims.SUBJECT, false);
            put(Claims.ISSUED_AT, false);
        }};
        requiredClaimsFB = new HashMap<String, Boolean>() {{
            put(Claims.USER_ID, false);
            put(Claims.APP_ID, false);
            put(Claims.ISSUED_AT, false);
        }};
        requiredClaimsRisc = new HashMap<String, Boolean>() {{
            put(Claims.JWT_ID, false);
            put(Claims.ISSUER, false);
            put(Claims.SUBJECT, false);
            put(Claims.ISSUED_AT, false);
        }};
        requiredClaimsScoped = new HashMap<String, Boolean>() {{
            put(Claims.SCOPE, false);
            put(Claims.ISSUER, false);
            put(Claims.SUBJECT, false);
            put(Claims.ISSUED_AT, false);
        }};
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

    private void verifyClaims() throws RequiredClaimException {
        Map<String, Boolean> requiredClaims = null;

        if(this instanceof ImplicitJwtCreator) {
            requiredClaims = requiredClaimsImplicit;
        } else if(this instanceof GoogleJwtCreator) {
            requiredClaims = requiredClaimsGoogle;
        } else if(this instanceof AccessJwtCreator) {
            requiredClaims = requiredClaimsAccess;
        } else if(this instanceof FbJwtCreator) {
            requiredClaims = requiredClaimsFB;
        } else if(this instanceof RiscJwtCreator) {
            requiredClaims = requiredClaimsRisc;
        } else if(this instanceof ScopedJwtCreator) {
            requiredClaims = requiredClaimsScoped;
        }

        for(String claim : requiredClaims.keySet())
            if(!requiredClaims.get(claim))
                throw new RequiredClaimException("Standard claim: " + claim + " has not been set");
    }
}
