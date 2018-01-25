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

import com.auth0.jwt.jwts.JWT;
import java.util.Date;
import java.util.List;

public interface Verification {
    Verification withIssuer(String... issuer);

    Verification withSubject(String... subject);

    Verification withAudience(String... audience);

    Verification acceptLeeway(long leeway) throws IllegalArgumentException;

    Verification acceptExpiresAt(long leeway) throws IllegalArgumentException;

    Verification acceptNotBefore(long leeway) throws IllegalArgumentException;

    Verification acceptIssuedAt(long leeway) throws IllegalArgumentException;

    Verification withJWTId(String jwtId);

    Verification withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Integer value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Long value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Double value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, String value) throws IllegalArgumentException;

    Verification withNonStandardClaim(String name, Date value) throws IllegalArgumentException;

    Verification withArrayClaim(String name, String... items) throws IllegalArgumentException;

    Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException;

    Verification withNbf(long nbf);

    Verification createVerifierForScoped(String scope, List<String> issuer,
                                         List<String> audience, long expLeeway, long iatLeeway);

    Verification createVerifierForImplicit(List<String> issuer,
                                           List<String> audience, long iatLeeway);

    Verification createVerifierForFb(String userId, String appId);

    Verification withUserId(String userId);

    Verification withAppId(String appId);

    Verification createVerifierForAccess(List<String> issuer,
                                         List<String> audience, long expLeeway, long iatLeeway);

    Verification createVerifierForRisc(String jti, List<String> issuer,
                                       List<String> audience, long iatLeeway, long expLeeway, long nbf);

    JWT build();
}
