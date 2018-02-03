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

package com.auth0.jwt.creators;

import com.auth0.jwt.oiccli.Token;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class Message implements Cloneable{

    private String state;
    private String code;
    private String claim;
    private String accessToken;
    private Integer expiresIn;
    private String tokenType;
    private String scope;
    private Token idToken;
    private String refreshToken;

    public String toUrlEncoded() throws UnsupportedEncodingException, NoSuchFieldException {
        return URLEncoder.encode(json, "UTF-8");
    }

    public String toUrlDecoded(String urlEncoded) throws UnsupportedEncodingException {
        return URLDecoder.decode(urlEncoded, "UTF-8");
    }

    public String toJSON(Map<String,Object> hashMap) {
        return new Gson().toJson(hashMap);
    }

    public HashMap<String,Object> fromJSON(String json) throws IOException {
        return new ObjectMapper().readValue(json, new TypeReference<Map<String, Object>>(){});
    }

    public Map getCParam() {
        throw new UnsupportedOperationException();
    }

    public String getState() {
        return state;
    }

    public String getCode() {
        return code;
    }

    public String getClaim() {
        return claim;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getScope() {
        return scope;
    }

    public Token getIdToken() {
        return idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Object clone() throws CloneNotSupportedException{
        return super.clone();
    }
}