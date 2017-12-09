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

package com.auth0.jwt.impl;

import org.hamcrest.collection.IsMapContaining;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class ClaimsHolderTest {

    @SuppressWarnings("RedundantCast")
    @Test
    public void shouldGetClaims() throws Exception {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("iss", "auth0");
        ClaimsHolder holder = new ClaimsHolder(claims);
        assertThat(holder, is(notNullValue()));
        assertThat(holder.getClaims(), is(notNullValue()));
        assertThat(holder.getClaims(), is(instanceOf(Map.class)));
        assertThat(holder.getClaims(), is(IsMapContaining.hasEntry("iss", (Object) "auth0")));
    }

    @Test
    public void shouldGetNotNullClaims() throws Exception {
        ClaimsHolder holder = new ClaimsHolder(null);
        assertThat(holder, is(notNullValue()));
        assertThat(holder.getClaims(), is(notNullValue()));
        assertThat(holder.getClaims(), is(instanceOf(Map.class)));
    }
}