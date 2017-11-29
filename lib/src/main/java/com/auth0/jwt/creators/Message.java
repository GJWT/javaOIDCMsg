package com.auth0.jwt.creators;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class Message {

    public String toUrlEncoded(String json) throws UnsupportedEncodingException {
        return URLEncoder.encode(json, "UTF-8");
    }

    public String toUrlDecoded(String urlEncoded) throws UnsupportedEncodingException {
        return URLDecoder.decode(urlEncoded, "UTF-8");
    }

    public String toJSON(HashMap<String,Object> hashMap) {
        return new Gson().toJson(hashMap);
    }

    public HashMap<String,Object> fromJSON(String json) throws IOException {
        return new ObjectMapper().readValue(json, new TypeReference<Map<String, Object>>(){});
    }

}