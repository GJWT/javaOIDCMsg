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
 * The GoogleJwtCreator class holds the sign method to generate a complete Google JWT (with Signature) from a given Header and Payload content.
 */
public class GoogleJwtCreator extends GoogleOrFbJwtCreator {

    protected GoogleJwtCreator() {
    }


    /**
     * Add a specific Name ("name") claim to the Payload.
     *
     * @param name the Name value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withName(String name) {
        jwt.withNonStandardClaim(Claims.NAME, name);
        requiredClaimsGoogle.put(Claims.NAME, true);
        return this;
    }

    /**
     * Add a specific Email ("email") claim to the Payload.
     *
     * @param email the Email value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withEmail(String email) {
        jwt.withNonStandardClaim(Claims.EMAIL, email);
        requiredClaimsGoogle.put(Claims.EMAIL, true);
        return this;
    }

    /**
     * Add a specific Picture ("picture") claim to the Payload.
     *
     * @param picture the Picture value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withPicture(String picture) {
        jwt.withNonStandardClaim(Claims.PICTURE, picture);
        requiredClaimsGoogle.put(Claims.PICTURE, true);
        return this;
    }

    /**
     * Add a specific Issuer ("issuer") claim to the Payload.
     *
     * @param issuer the Issuer value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withIssuer(String issuer) {
        jwt.withIssuer(issuer);
        requiredClaimsGoogle.put(Claims.ISSUER, true);
        return this;
    }

    /**
     * Add a specific Subject ("subject") claim to the Payload.
     *
     * @param subject the Subject value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withSubject(String subject) {
        jwt.withSubject(subject);
        requiredClaimsGoogle.put(Claims.SUBJECT, true);
        return this;
    }

    /**
     * Add a specific Audience ("audience") claim to the Payload.
     * Allows for multiple audience
     *
     * @param audience the Audience value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withAudience(String... audience) {
        jwt.withAudience(audience);
        return this;
    }

    /**
     * Add a specific Issued At ("iat") claim to the Payload.
     *
     * @param iat the Issued At value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withIat(Date iat) {
        jwt.withIssuedAt(iat);
        requiredClaimsGoogle.put(Claims.ISSUED_AT, true);
        return this;
    }

    /**
     * Add a specific Expires At ("exp") claim to the Payload.
     *
     * @param exp the Expires At value.
     * @return this same Builder instance.
     */
    public GoogleJwtCreator withExp(Date exp) {
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
    public GoogleJwtCreator withNonStandardClaim(String name, String value) {
        if(Claims.NAME.equalsIgnoreCase(value)) {
            withName(value);
        } else if(Claims.EMAIL.equalsIgnoreCase(value)) {
            withEmail(value);
        } else if(Claims.PICTURE.equalsIgnoreCase(value)) {
            withPicture(value);
        } else if(Claims.ISSUER.equalsIgnoreCase(value) || "issuer".equalsIgnoreCase(value)) {
            withIssuer(value);
        } else if("subject".equalsIgnoreCase(name) || Claims.SUBJECT.equalsIgnoreCase(name)) {
            withSubject(value);
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
    public GoogleJwtCreator withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
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
    public GoogleJwtCreator withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
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
    public GoogleJwtCreator withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
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
    public GoogleJwtCreator withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
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
    public GoogleJwtCreator withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
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
    public GoogleJwtCreator withArrayClaim(String name, String... items) throws IllegalArgumentException {
        jwt.withArrayClaim(name, items);
        if(requiredClaimsGoogle.containsKey(name))
            requiredClaimsGoogle.put(name, true);
        return this;
    }

    /**
     * Developer explicitly specifies whether they want to accept
     * NONE algorithms or not.
     *
     * @param isNoneAlgorithmAllowed
     * @return
     */
    public GoogleJwtCreator setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
        jwt.setIsNoneAlgorithmAllowed(isNoneAlgorithmAllowed);
        return this;
    }

    public static GoogleJwtCreator build() {
        return new GoogleJwtCreator();
    }
}
