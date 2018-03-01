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
 * The AccessJwtCreator class holds the sign method to generate a complete Access JWT (with Signature) from a given Header and Payload content.
 */
public class AccessJwtCreator extends Creator{

    private AccessJwtCreator() {
    }

    /**
     * Add a specific Issuer ("issuer") claim to the Payload.
     *
     * @param issuer the Issuer value.
     * @return this same Builder instance.
     */
    public AccessJwtCreator withIssuer(String issuer) {
        jwt.withIssuer(issuer);
        requiredClaimsAccess.put(Claims.ISSUER, true);
        return this;
    }

    /**
     * Add a specific Subject ("subject") claim to the Payload.
     *
     * @param subject the Subject value.
     * @return this same Builder instance.
     */
    public AccessJwtCreator withSubject(String subject) {
        jwt.withSubject(subject);
        requiredClaimsAccess.put(Claims.SUBJECT, true);
        return this;
    }

    /**
     * Add a specific Audience ("audience") claim to the Payload.
     * Allows for multiple audience
     *
     * @param audience the Audience value.
     * @return this same Builder instance.
     */
    public AccessJwtCreator withAudience(String... audience) {
        jwt.withAudience(audience);
        return this;
    }

    /**
     * Add a specific Issued At ("iat") claim to the Payload.
     *
     * @param iat the Issued At value.
     * @return this same Builder instance.
     */
    public AccessJwtCreator withIat(Date iat) {
        jwt.withIssuedAt(iat);
        requiredClaimsAccess.put(Claims.ISSUED_AT, true);
        return this;
    }

    /**
     * Add a specific Expires At ("exp") claim to the Payload.
     *
     * @param exp the Expires At value.
     * @return this same Builder instance.
     */
    public AccessJwtCreator withExp(Date exp) {
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
    public AccessJwtCreator withNonStandardClaim(String name, String value) {
        if("subject".equalsIgnoreCase(name) || Claims.SUBJECT.equalsIgnoreCase(name)) {
            withSubject(value);
        } else if("issuer".equalsIgnoreCase(name) || Claims.ISSUER.equalsIgnoreCase(name)) {
            withIssuer(value);
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
    public AccessJwtCreator withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
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
    public AccessJwtCreator withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
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
    public AccessJwtCreator withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
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
    public AccessJwtCreator withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
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
    public AccessJwtCreator withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
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
    public AccessJwtCreator withArrayClaim(String name, String... items) throws IllegalArgumentException {
        jwt.withArrayClaim(name, items);
        if(requiredClaimsAccess.containsKey(name))
            requiredClaimsAccess.put(name, true);
        return this;
    }

    /**
     * Developer explicitly specifies whether they want to accept
     * NONE algorithms or not.
     *
     * @param isNoneAlgorithmAllowed
     * @return
     */
    public AccessJwtCreator setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
        jwt.setIsNoneAlgorithmAllowed(isNoneAlgorithmAllowed);
        return this;
    }

    public static AccessJwtCreator build() {
        return new AccessJwtCreator();
    }
}
