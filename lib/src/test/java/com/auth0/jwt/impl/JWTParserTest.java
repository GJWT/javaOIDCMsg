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

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.auth0.jwt.impl.JWTParser.getDefaultObjectMapper;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class JWTParserTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private JWTParser parser;

    @Before
    public void setUp() throws Exception {
        parser = new JWTParser();
    }

    @Test
    public void shouldGetDefaultObjectMapper() throws Exception {
        ObjectMapper mapper = getDefaultObjectMapper();
        assertThat(mapper, is(notNullValue()));
        assertThat(mapper, is(instanceOf(ObjectMapper.class)));
        assertThat(mapper.isEnabled(SerializationFeature.FAIL_ON_EMPTY_BEANS), is(false));
    }

    @Test
    public void shouldAddDeserializers() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        new JWTParser(mapper);
        verify(mapper).registerModule(any(Module.class));
    }

    @Test
    public void shouldParsePayload() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        JWTParser parser = new JWTParser(mapper);
        parser.parsePayload("{}");

        verify(mapper).readValue("{}", Payload.class);
    }

    @Test
    public void shouldThrowOnInvalidPayload() throws Exception {
        String jsonPayload = "{{";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", jsonPayload));
        Payload payload = parser.parsePayload(jsonPayload);
        assertThat(payload, is(nullValue()));
    }

    @Test
    public void shouldParseHeader() throws Exception {
        ObjectMapper mapper = mock(ObjectMapper.class);
        JWTParser parser = new JWTParser(mapper);
        parser.parseHeader("{}");

        verify(mapper).readValue("{}", Header.class);
    }

    @Test
    public void shouldThrowOnInvalidHeader() throws Exception {
        String jsonHeader = "}}";
        exception.expect(JWTDecodeException.class);
        exception.expectMessage(String.format("The string '%s' doesn't have a valid JSON format.", jsonHeader));
        Header header = parser.parseHeader(jsonHeader);
        assertThat(header, is(nullValue()));
    }

    @Test
    public void shouldConvertFromValidJSON() throws Exception {
        String json = "\r\n { \r\n } \r\n";
        Object object = parser.convertFromJSON(json, Object.class);
        assertThat(object, is(notNullValue()));
    }

    @Test
    public void shouldThrowWhenConvertingIfNullJson() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The string 'null' doesn't have a valid JSON format.");
        String json = null;
        Object object = parser.convertFromJSON(json, Object.class);
        assertThat(object, is(nullValue()));
    }

    @Test
    public void shouldThrowWhenConvertingFromInvalidJson() throws Exception {
        exception.expect(JWTDecodeException.class);
        exception.expectMessage("The string '}{' doesn't have a valid JSON format.");
        String json = "}{";
        Object object = parser.convertFromJSON(json, Object.class);
        assertThat(object, is(nullValue()));
    }
}