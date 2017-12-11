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

package com.auth0.jwt.interfaces;

/**
 * The Header class represents the 1st part of the JWT, where the Header value is hold.
 */
public interface Header {

    /**
     * Getter for the Algorithm "alg" claim defined in the JWT's Header. If the claim is missing it will return null.
     *
     * @return the Algorithm defined or null.
     */
    String getAlgorithm();

    /**
     * Getter for the Type "typ" claim defined in the JWT's Header. If the claim is missing it will return null.
     *
     * @return the Type defined or null.
     */
    String getType();

    /**
     * Getter for the Content Type "cty" claim defined in the JWT's Header. If the claim is missing it will return null.
     *
     * @return the Content Type defined or null.
     */
    String getContentType();

    /**
     * Get the value of the "kid" claim, or null if it's not available.
     *
     * @return the Key ID value or null.
     */
    String getKeyId();

    /**
     * Get a Private Claim given it's name. If the Claim wasn't specified in the Header, a NullClaim will be returned.
     *
     * @param name the name of the Claim to retrieve.
     * @return a non-null Claim.
     */
    Claim getHeaderClaim(String name);
}
