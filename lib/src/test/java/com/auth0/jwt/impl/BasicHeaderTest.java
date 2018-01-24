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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.hamcrest.collection.IsMapContaining;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.HashMap;
import java.util.Map;

public class BasicHeaderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldHaveUnmodifiableTreeWhenInstantiatedWithNonNullTree() throws Exception {
        exception.expect(UnsupportedOperationException.class);
        BasicHeader header = new BasicHeader(null, null, null, null, new HashMap<String, JsonNode>());
        header.getTree().put("something", null);
    }

    @Test
    public void shouldHaveUnmodifiableTreeWhenInstantiatedWithNullTree() throws Exception {
        exception.expect(UnsupportedOperationException.class);
        BasicHeader header = new BasicHeader(null, null, null, null, null);
        header.getTree().put("something", null);
    }

    @Test
    public void shouldHaveTree() throws Exception {
        HashMap<String, JsonNode> map = new HashMap<>();
        JsonNode node = NullNode.getInstance();
        map.put("key", node);
        BasicHeader header = new BasicHeader(null, null, null, null, map);

        assertThat(header.getTree(), is(notNullValue()));
        assertThat(header.getTree(), is(IsMapContaining.hasEntry("key", node)));
    }

    @Test
    public void shouldGetAlgorithm() throws Exception {
        BasicHeader header = new BasicHeader("HS256", null, null, null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(notNullValue()));
        assertThat(header.getAlgorithm(), is("HS256"));
    }

    @Test
    public void shouldGetNullAlgorithmIfMissing() throws Exception {
        BasicHeader header = new BasicHeader(null, null, null, null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getAlgorithm(), is(nullValue()));
    }

    @Test
    public void shouldGetType() throws Exception {
        BasicHeader header = new BasicHeader(null, "jwt", null, null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getType(), is(notNullValue()));
        assertThat(header.getType(), is("jwt"));
    }

    @Test
    public void shouldGetNullTypeIfMissing() throws Exception {
        BasicHeader header = new BasicHeader(null, null, null, null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getType(), is(nullValue()));
    }

    @Test
    public void shouldGetContentType() throws Exception {
        BasicHeader header = new BasicHeader(null, null, "content", null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getContentType(), is(notNullValue()));
        assertThat(header.getContentType(), is("content"));
    }

    @Test
    public void shouldGetNullContentTypeIfMissing() throws Exception {
        BasicHeader header = new BasicHeader(null, null, null, null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getContentType(), is(nullValue()));
    }

    @Test
    public void shouldGetKeyId() throws Exception {
        BasicHeader header = new BasicHeader(null, null, null, "key", null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getKeyId(), is(notNullValue()));
        assertThat(header.getKeyId(), is("key"));
    }

    @Test
    public void shouldGetNullKeyIdIfMissing() throws Exception {
        BasicHeader header = new BasicHeader(null, null, null, null, null);

        assertThat(header, is(notNullValue()));
        assertThat(header.getKeyId(), is(nullValue()));
    }

    @Test
    public void shouldGetExtraClaim() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        tree.put("extraClaim", new TextNode("extraValue"));
        BasicHeader header = new BasicHeader(null, null, null, null, tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getHeaderClaim("extraClaim"), is(instanceOf(JsonNodeClaim.class)));
        assertThat(header.getHeaderClaim("extraClaim").asString(), is("extraValue"));
    }

    @Test
    public void shouldGetNotNullExtraClaimIfMissing() throws Exception {
        Map<String, JsonNode> tree = new HashMap<>();
        BasicHeader header = new BasicHeader(null, null, null, null, tree);

        assertThat(header, is(notNullValue()));
        assertThat(header.getHeaderClaim("missing"), is(notNullValue()));
        assertThat(header.getHeaderClaim("missing"), is(instanceOf(NullClaim.class)));
    }
}