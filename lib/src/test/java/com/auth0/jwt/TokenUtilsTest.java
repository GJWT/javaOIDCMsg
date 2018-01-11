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

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.utils.TokenUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class TokenUtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldSplitToken() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc";
        String[] parts = TokenUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is("W1mx_Y0hbAMbPmfW9whT605AAcxB7REFuJiDAHk2Sdc"));
    }

    @Test
    public void shouldSplitTokenWithEmptySignature() throws Exception {
        String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.";
        String[] parts = TokenUtils.splitToken(token);

        assertThat(parts, is(notNullValue()));
        assertThat(parts, is(arrayWithSize(3)));
        assertThat(parts[0], is("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"));
        assertThat(parts[1], is("eyJpc3MiOiJhdXRoMCJ9"));
        assertThat(parts[2], is(isEmptyString()));
    }

    @Test
    public void shouldThrowOnSplitTokenWithMoreThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 4.");
        String token = "this.has.four.parts";
        TokenUtils.splitToken(token);
    }

    @Test
    public void shouldThrowOnSplitTokenWithLessThan3Parts() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The token was expected to have 3 parts, but got 2.");
        String token = "two.parts";
        TokenUtils.splitToken(token);
    }
}