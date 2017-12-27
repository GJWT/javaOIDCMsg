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

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.GoogleVerification;
import com.auth0.jwt.interfaces.Verification;

import java.util.List;

public class ExtendedJWT extends GoogleJWT {

    ExtendedJWT(Algorithm algorithm) throws IllegalArgumentException {
        super(algorithm);
    }


    public Verification createVerifierForExtended(String picture, String email, List<String> issuer,
                                                List<String> audience, String name, long nbf, long expLeeway, long iatLeeway) {
        Verification verification = createVerifierForGoogle(picture, email, issuer, audience, name, expLeeway, iatLeeway);
        return verification.withNbf(nbf);
    }

    public static GoogleVerification require(Algorithm algorithm) {
        return ExtendedJWT.init(algorithm);
    }

    static GoogleVerification init(Algorithm algorithm) throws IllegalArgumentException {
        return new ExtendedJWT(algorithm);
    }

    /**
     * Require a specific Not Before ("nbf") claim.
     *
     * @param nbf the required Not Before value
     * @return this same Verification instance.
     */
    @Override
    public Verification withNbf(long nbf) {
        requireClaim("nbf", nbf);
        return this;
    }

}
