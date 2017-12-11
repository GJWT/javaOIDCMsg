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

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The Payload class represents the 2nd part of the JWT, where the Payload value is hold.
 */
public interface Payload {

    /**
     * Get the value(s) of the "iss" claim, or null if it's not available.
     *
     * @return the Issuer value or null.
     */
    List<String> getIssuer();

    /**
     * Get the value(s) of the "sub" claim, or null if it's not available.
     *
     * @return the Subject value or null.
     */
    List<String> getSubject();

    /**
     * Get the value(s) of the "aud" claim, or null if it's not available.
     *
     * @return the Audience value or null.
     */
    List<String> getAudience();

    /**
     * Get the value of the "exp" claim, or null if it's not available.
     *
     * @return the Expiration Time value or null.
     */
    Date getExpiresAt();

    /**
     * Get the value of the "nbf" claim, or null if it's not available.
     *
     * @return the Not Before value or null.
     */
    Date getNotBefore();

    /**
     * Get the value of the "iat" claim, or null if it's not available.
     *
     * @return the Issued At value or null.
     */
    Date getIssuedAt();

    /**
     * Get the value of the "jti" claim, or null if it's not available.
     *
     * @return the JWT ID value or null.
     */
    String getId();

    /**
     * Get a Claim given it's name. If the Claim wasn't specified in the Payload, a NullClaim will be returned.
     *
     * @param name the name of the Claim to retrieve.
     * @return a non-null Claim.
     */
    Claim getClaim(String name);

    /**
     * Get the Claims defined in the Token.
     *
     * @return a non-null Map containing the Claims defined in the Token.
     */
    Map<String, Claim> getClaims();
}
