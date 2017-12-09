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

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class NullClaimTest {
    private NullClaim claim;

    @Before
    public void setUp() throws Exception {
        claim = new NullClaim();
    }

    @Test
    public void shouldBeNull() throws Exception {
        assertThat(claim.isNull(), is(true));
    }

    @Test
    public void shouldGetAsBoolean() throws Exception {
        assertThat(claim.asBoolean(), is(nullValue()));
    }

    @Test
    public void shouldGetAsInt() throws Exception {
        assertThat(claim.asInt(), is(nullValue()));
    }

    @Test
    public void shouldGetAsLong() throws Exception {
        assertThat(claim.asLong(), is(nullValue()));
    }

    @Test
    public void shouldGetAsDouble() throws Exception {
        assertThat(claim.asDouble(), is(nullValue()));
    }

    @Test
    public void shouldGetAsString() throws Exception {
        assertThat(claim.asString(), is(nullValue()));
    }

    @Test
    public void shouldGetAsDate() throws Exception {
        assertThat(claim.asDate(), is(nullValue()));
    }

    @Test
    public void shouldGetAsArray() throws Exception {
        assertThat(claim.asArray(Object.class), is(nullValue()));
    }

    @Test
    public void shouldGetAsList() throws Exception {
        assertThat(claim.asList(Object.class), is(nullValue()));
    }

    @Test
    public void shouldGetAsMap() throws Exception {
        assertThat(claim.asMap(), is(nullValue()));
    }

    @Test
    public void shouldGetAsCustomClass() throws Exception {
        assertThat(claim.as(Object.class), is(nullValue()));
    }

}