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

package com.auth0.jwt.verification;

import com.auth0.jwt.TimeUtil;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.creators.ImplicitJwtCreator;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwt.jwts.ImplicitJWT;
import com.auth0.jwt.jwts.JWT;
import com.auth0.jwt.verification.VerificationAndAssertion;
import static java.util.Arrays.asList;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class VerificationAndAssertionTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testAssertPositiveWithNegativeNumber() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Leeway value can't be negative.");

        VerificationAndAssertion.assertPositive(-1);
    }

    @Test
    public void testAssertNullWithNullString() throws Exception {
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("The Custom Claim's name can't be null.");

        VerificationAndAssertion.assertNonNull(null);
    }

    @Test
    public void testVerifyAlgorithmWithMismatchingAlgorithms() throws Exception {
        thrown.expect(AlgorithmMismatchException.class);
        thrown.expectMessage("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = ImplicitJwtCreator.build()
                .withIssuer("accounts.fake.com")
                .withSubject("subject")
                .withAudience("audience")
                .withIat(TimeUtil.generateRandomIatDateInPast())
                .sign(algorithm);
        Verification verification = ImplicitJWT.require(Algorithm.none());
        JWT verifier = verification.createVerifierForImplicit(asList("accounts.fake.com"), asList("audience"), 1).build();
        DecodedJWT jwt = verifier.decode(token);
    }

}
