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

package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.jwts.JWT;
import java.util.Date;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class JWTTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testWithNbf() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).withNbf(5);
    }

    @Test
    public void testCreateVerifierForRisc() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).createVerifierForRisc(null, null, null, 5, 5, 5);
    }

    @Test
    public void testCreateVerifierForScoped() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).createVerifierForScoped(null, null, null, 5, 5);
    }

    @Test
    public void testCreateVerifierForImplicit() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).createVerifierForImplicit(null, null,  5);
    }

    @Test
    public void testCreateVerifierForFB() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).createVerifierForFb(null, null);
    }

    @Test
    public void testCreateVerifierForAccess() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).createVerifierForAccess(null, null, 5, 5);
    }

    @Test
    public void testWithUserId() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).withUserId(null);
    }

    @Test
    public void testWithAppId() {
        thrown.expect(UnsupportedOperationException.class);
        thrown.expectMessage("this method has not been implemented");
        JWT.require(Algorithm.none()).withAppId(null);
    }

    @Test
    public void testWithSubjectId() {
        JWT.require(Algorithm.none()).withSubject("subject1", "subject2");
    }

    @Test
    public void testAcceptLeeway() {
        JWT.require(Algorithm.none()).acceptLeeway(5);
    }

    @Test
    public void testAcceptNotBefore() {
        JWT.require(Algorithm.none()).acceptNotBefore(5);
    }

    @Test
    public void testWithJWTId() {
        JWT.require(Algorithm.none()).withJWTId("jwtId");
    }

    @Test
    public void testJWTNonStandardClaimBoolean() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", true);
    }

    @Test
    public void testJWTNonStandardClaimInteger() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", 5);
    }

    @Test
    public void testJWTNonStandardClaimLong() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", 5L);
    }

    @Test
    public void testJWTNonStandardClaimDouble() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", 9.99);
    }

    @Test
    public void testJWTNonStandardClaimString() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", "nonStandardClaimValue");
    }

    @Test
    public void testJWTNonStandardClaimDate() throws Exception {
        JWT.require(Algorithm.none()).withNonStandardClaim("nonStandardClaim", new Date());
    }

    @Test
    public void testJWTWithArrayClaimStrings() throws Exception {
        JWT.require(Algorithm.none()).withArrayClaim("arrayKey", "arrayValue1", "arrayValue2");
    }

    @Test
    public void testJWTWithArrayClaimIntegers() throws Exception {
        JWT.require(Algorithm.none()).withArrayClaim("arrayKey", 1, 2).build();
    }

    @Test
    public void testJWTNullAlgorithm() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Algorithm cannot be null.");
        JWT.require(null);
    }
}
