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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import com.auth0.jwt.UserPojo;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

public class PayloadSerializerTest {

    private StringWriter writer;
    private PayloadSerializer serializer;
    private JsonGenerator jsonGenerator;
    private SerializerProvider serializerProvider;

    @Before
    public void setUp() throws Exception {
        writer = new StringWriter();
        serializer = new PayloadSerializer();
        jsonGenerator = new JsonFactory().createGenerator(writer);
        ObjectMapper mapper = new ObjectMapper();
        jsonGenerator.setCodec(mapper);
        serializerProvider = mapper.getSerializerProvider();
    }

    @SuppressWarnings("Convert2Diamond")
    @Test
    public void shouldSerializeEmptyMap() throws Exception {
        ClaimsHolder holder = new ClaimsHolder(new HashMap<String, Object>());
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{}")));
    }

    @Test
    public void shouldSerializeStringAudienceAsString() throws Exception {
        ClaimsHolder holder = holderFor("aud", "auth0");
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"aud\":\"auth0\"}")));
    }

    @Test
    public void shouldSerializeSingleItemAudienceAsArray() throws Exception {
        ClaimsHolder holder = holderFor("aud", new String[]{"auth0"});
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"aud\":\"auth0\"}")));
    }

    @Test
    public void shouldSerializeMultipleItemsAudienceAsArray() throws Exception {
        ClaimsHolder holder = holderFor("aud", new String[]{"auth0", "auth10"});
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"aud\":[\"auth0\",\"auth10\"]}")));
    }

    @Test
    public void shouldSkipSerializationOnEmptyAudience() throws Exception {
        ClaimsHolder holder = holderFor("aud", new String[0]);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{}")));
    }

    @Test
    public void shouldSerializeNotBeforeDateInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("nbf", new Date(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"nbf\":1478874}")));
    }

    @Test
    public void shouldSerializeIssuedAtDateInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("iat", new Date(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"iat\":1478874}")));
    }

    @Test
    public void shouldSerializeExpiresAtDateInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("exp", new Date(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"exp\":1478874}")));
    }

    @Test
    public void shouldSerializeCustomDateInSeconds() throws Exception {
        ClaimsHolder holder = holderFor("birthdate", new Date(1478874000));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"birthdate\":1478874}")));
    }

    @Test
    public void shouldSerializeDatesUsingLong() throws Exception {
        long secs = Integer.MAX_VALUE + 10000L;
        Date date = new Date(secs * 1000L);
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("iat", date);
        claims.put("nbf", date);
        claims.put("exp", date);
        claims.put("ctm", date);
        ClaimsHolder holder = new ClaimsHolder(claims);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        String json = writer.toString();
        assertThat(json, containsString("\"iat\":2147493647"));
        assertThat(json, containsString("\"nbf\":2147493647"));
        assertThat(json, containsString("\"exp\":2147493647"));
        assertThat(json, containsString("\"ctm\":2147493647"));
    }

    @Test
    public void shouldSerializeStrings() throws Exception {
        ClaimsHolder holder = holderFor("name", "Auth0 Inc");
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"name\":\"Auth0 Inc\"}")));
    }

    @Test
    public void shouldSerializeIntegers() throws Exception {
        ClaimsHolder holder = holderFor("number", 12345);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"number\":12345}")));
    }

    @Test
    public void shouldSerializeDoubles() throws Exception {
        ClaimsHolder holder = holderFor("fraction", 23.45);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"fraction\":23.45}")));
    }

    @Test
    public void shouldSerializeBooleans() throws Exception {
        ClaimsHolder holder = holderFor("pro", true);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"pro\":true}")));
    }

    @Test
    public void shouldSerializeNulls() throws Exception {
        ClaimsHolder holder = holderFor("id", null);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"id\":null}")));
    }

    @Test
    public void shouldSerializeCustomArrayOfObject() throws Exception {
        UserPojo user1 = new UserPojo("Michael", 1);
        UserPojo user2 = new UserPojo("Lucas", 2);
        ClaimsHolder holder = holderFor("users", new UserPojo[]{user1, user2});
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"users\":[{\"name\":\"Michael\",\"id\":1},{\"name\":\"Lucas\",\"id\":2}]}")));
    }

    @Test
    public void shouldSerializeCustomListOfObject() throws Exception {
        UserPojo user1 = new UserPojo("Michael", 1);
        UserPojo user2 = new UserPojo("Lucas", 2);
        ClaimsHolder holder = holderFor("users", Arrays.asList(user1, user2));
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"users\":[{\"name\":\"Michael\",\"id\":1},{\"name\":\"Lucas\",\"id\":2}]}")));
    }

    @Test
    public void shouldSerializeCustomObject() throws Exception {
        UserPojo user = new UserPojo("Michael", 1);
        ClaimsHolder holder = holderFor("users", user);
        serializer.serialize(holder, jsonGenerator, serializerProvider);
        jsonGenerator.flush();

        assertThat(writer.toString(), is(equalTo("{\"users\":{\"name\":\"Michael\",\"id\":1}}")));
    }

    @SuppressWarnings("Convert2Diamond")
    private ClaimsHolder holderFor(String key, Object value) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(key, value);
        return new ClaimsHolder(map);
    }

}