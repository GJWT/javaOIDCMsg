package com.auth0.jwt.oiccli;

import com.auth0.jwt.creators.Message;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class AuthorizationRequest extends Message{

    private String responseType;
    private String clientId;
    private String redirectUri;

    public String toUrlEncoded() throws UnsupportedEncodingException, NoSuchFieldException {
        Field[] fields = this.getClass().getFields();
        String fieldString;
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < fields.length; i++) {
            fieldString = fields[i].toString();
            fieldString = fieldString.substring(fieldString.indexOf(".")+1);
            sb.append(fieldString+"="+this.getClass().getField(fieldString));
            if(i != fields.length-1) {
                sb.append("&");
            }
        }
        return URLEncoder.encode(sb.toString(), "UTF-8");
    }

    public String toJSON() throws NoSuchFieldException, IllegalAccessException {
        Field[] fields = this.getClass().getFields();
        String fieldString;
        StringBuilder sb = new StringBuilder();
        Map<String,Object> hMap = new HashMap<>();
        for(int i = 0; i < fields.length; i++) {
            fieldString = fields[i].toString();
            fieldString = fieldString.substring(fieldString.indexOf(".")+1);
            hMap.put(fieldString, this.getClass().getField(fieldString).get(this));
        }
        return toJSON(hMap);
    }

    public void update(Map<String, String> hMap) throws NoSuchFieldException, IllegalAccessException {
        for(String key : hMap.keySet()) {
            this.getClass().getField(key).set(this, hMap.get(key));
        }
    }
}
