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

import com.auth0.jwt.impl.Claims;
import java.util.Date;

/**
 * The FbJwtCreator class holds the sign method to generate a complete FB JWT (with Signature) from a given Header and Payload content.
 */
public class FbJwtCreator extends GoogleOrFbJwtCreator {

    private FbJwtCreator() {
    }

    /**
     * Add a specific Issued At ("iat") claim to the Payload.
     *
     * @param iat the Issued At value.
     * @return this same Builder instance.
     */
    public FbJwtCreator withIat(Date iat) {
        jwt.withIssuedAt(iat);
        requiredClaimsFB.put(Claims.ISSUED_AT, true);
        return this;
    }

    /**
     * Add a specific Expires At ("exp") claim to the Payload.
     *
     * @param exp the Expires At value.
     * @return this same Builder instance.
     */
    public FbJwtCreator withExp(Date exp) {
        jwt.withExpiresAt(exp);
        return this;
    }

    /**
     * Require a specific userId ("userId") claim.
     *
     * @param userId the required userId value
     * @return this same Verification instance.
     */
    public FbJwtCreator withUserId(String userId) {
        jwt.withNonStandardClaim(Claims.USER_ID, userId);
        requiredClaimsFB.put(Claims.USER_ID, true);
        return this;
    }

    /**
     * Require a specific appId ("appId") claim.
     *
     * @param appId the required appId value
     * @return this same Verification instance.
     */
    public FbJwtCreator withAppId(String appId) {
        jwt.withNonStandardClaim(Claims.APP_ID, appId);
        requiredClaimsFB.put(Claims.APP_ID, true);
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
    public FbJwtCreator withNonStandardClaim(String name, String value) {
        if(Claims.USER_ID.equalsIgnoreCase(name) || "user_id".equalsIgnoreCase(name)) {
            withUserId(value);
        } else if(Claims.APP_ID.equalsIgnoreCase(name) || "app_id".equalsIgnoreCase(name)) {
            withAppId(value);
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
    public FbJwtCreator withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
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
    public FbJwtCreator withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
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
    public FbJwtCreator withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
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
    public FbJwtCreator withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
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
    public FbJwtCreator withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
        if(Claims.ISSUED_AT.equalsIgnoreCase(name) || "issuedAt".equalsIgnoreCase(name) || "issued_at".equalsIgnoreCase(name)) {
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
    public FbJwtCreator withArrayClaim(String name, String... items) throws IllegalArgumentException {
        jwt.withArrayClaim(name, items);
        if(requiredClaimsFB.containsKey(name))
            requiredClaimsFB.put(name, true);
        return this;
    }

    /**
     * Developer explicitly specifies whether they want to accept
     * NONE algorithms or not.
     *
     * @param isNoneAlgorithmAllowed
     * @return
     */
    public FbJwtCreator setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
        jwt.setIsNoneAlgorithmAllowed(isNoneAlgorithmAllowed);
        return this;
    }

    public static FbJwtCreator build() {
        return new FbJwtCreator();
    }
}
