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

package com.auth0.jwt.jwts;

import com.auth0.jwt.ClockImpl;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.interfaces.Verification;
import java.util.List;

public class GoogleJWT extends JWT.BaseVerification implements GoogleVerification {

    GoogleJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }

    /**
     * Create Verification object for verification purposes
     *
     * @param picture
     * @param email
     * @param issuer
     * @param audience
     * @param name
     * @return
     */
    @Override
    public Verification createVerifierForGoogle(String picture, String email, List<String> issuer,
                                                List<String> audience, String name, long expLeeway, long iatLeeway) {
        return withPicture(picture).withName(name).withEmail(email).withIssuer(issuer.toArray(new String[issuer.size()])).withAudience(audience.toArray(new String[audience.size()]))
                .acceptExpiresAt(expLeeway).acceptIssuedAt(iatLeeway);
    }

    /**
     * Require a specific Picture ("picture") claim.
     *
     * @param picture the required Picture value
     * @return this same Verification instance.
     */
    @Override
    public GoogleVerification withPicture(String picture) {
        requireClaim(Constants.PICTURE, picture);
        return this;
    }

    /**
     * Require a specific Email ("email") claim.
     *
     * @param email the required Email value
     * @return this same Verification instance.
     */
    @Override
    public GoogleVerification withEmail(String email) {
        requireClaim(Constants.EMAIL, email);
        return this;
    }

    /**
     * Require a specific Name ("name") claim.
     *
     * @param name the required Name value
     * @return this same Verification instance.
     */
    @Override
    public GoogleVerification withName(String name) {
        requireClaim("name", name);
        return this;
    }

    @Override
    public Verification createVerifierForExtended(String picture, String email, List<String> issuer, List<String> audience, String name, long nbf, long expLeeway, long iatLeeway) {
        throw new UnsupportedOperationException("you shouldn't be calling this method");
    }

    /**
     * Returns a {GoogleVerification} to be used to validate token signature.
     *
     * @param algorithm that will be used to verify the token's signature.
     * @return GoogleVerification
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    public static GoogleVerification require(Algorithm algorithm) {
        return GoogleJWT.init(algorithm);
    }

    /**
     * Initialize a GoogleVerification instance using the given Algorithm.
     *
     * @param algorithm the Algorithm to use on the JWT verification.
     * @return a GoogleJWT instance to configure.
     * @throws IllegalArgumentException if the provided algorithm is null.
     */
    static GoogleVerification init(Algorithm algorithm) throws IllegalArgumentException {
        return new GoogleJWT(algorithm);
    }

    /**
     * Creates a new and reusable instance of the JWT with the configuration already provided.
     *
     * @return a new JWT instance.
     */
    @Override
    public JWT build() {
        return this.build(new ClockImpl());
    }

    /**
     * Creates a new and reusable instance of the JWT the configuration already provided.
     * ONLY FOR TEST PURPOSES.
     *
     * @param clock the instance that will handle the current time.
     * @return a new JWT instance with a custom Clock.
     */
    @Override
    public JWT build(Clock clock) {
        addLeewayToDateClaims();
        return new JWT(algorithm, claims, clock);
    }
}
