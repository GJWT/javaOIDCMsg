package com.auth0.jwt.oicmsg.oic;

import com.auth0.jwt.oicmsg.Message;
import com.auth0.jwt.oicmsg.Tuple5;
import com.auth0.jwt.oicmsg.exceptions.AtHashError;
import com.auth0.jwt.oicmsg.exceptions.CHashError;
import com.auth0.jwt.oicmsg.exceptions.MissingRequiredAttribute;
import com.auth0.jwt.oicmsg.exceptions.VerificationError;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuthorizationResponse extends com.auth0.jwt.oicmsg.oauth2.AuthorizationResponse{

    public AuthorizationResponse() {
        Map<String,Tuple5> cParamAuthorizationResponse = new HashMap<>(getClaims());
        //c_param.update(oauth2.AccessTokenResponse.c_param) HOW TO DEAL WITH MULTIPLE INHERITANCE?
        cParamAuthorizationResponse.put("code", SINGLE_OPTIONAL_STRING);
        cParamAuthorizationResponse.put("accessToken", SINGLE_OPTIONAL_STRING);
        cParamAuthorizationResponse.put("tokenType", SINGLE_OPTIONAL_STRING);
        cParamAuthorizationResponse.put("idToken", new Tuple5(Arrays.asList(Message.class), false, msgSer, null, false));

        updateClaims(cParamAuthorizationResponse);
    }

    public boolean verify(Map<String,Object> kwargs) throws Exception {
        super.verify(kwargs);
        Map<String,Object> claims = getDict();
        if(claims.containsKey("audience")) {
            if (kwargs.containsKey("clientId")) {
                if(claims.get("audience") instanceof List
                        && ((List) claims.get("audience")).contains(kwargs.get("clientId"))) {
                    return false;
                }
            }
        }

        if(claims.containsKey("idToken")) {
            Map<String,Object> args = new HashMap<>();
            List<String> argsTemp = Arrays.asList("key", "keyjar", "algs", "sender");
            for(String arg : argsTemp) {
                args.put(arg, kwargs.get(arg));
            }
            Object idToken = claims.get("idToken");
            if(!(idToken instanceof String)) {
                throw new IllegalArgumentException("idToken should be of type String");
            }
            String idTokenString = (String) idToken;
            IdToken idt = new IdToken().fromJWT(idTokenString, args);
            if(!idt.verify(kwargs)) {
                throw new VerificationError("Could not verify idToken " + idt);
            }

            String algorithm = idt.getJwsHeader("alg");

            String hashFunction = "HS" + algorithm.substring(algorithm.length()-3);

            if(claims.containsKey("accessToken")) {
                if(idt.getAtHash() == null) {
                    throw new MissingRequiredAttribute("Missing atHash property " + idt);
                }
                Object accessToken = claims.get("accessToken");
                if(!(accessToken instanceof String)) {
                    throw new IllegalArgumentException("accessToken should be of type String");
                }
                String accessTokenString = (String) accessToken;
                if(!idt.getAtHash().equals(JWS.leftHash(accessTokenString, hashFunction))) {
                    throw new AtHashError("Failed to verify accessToken hash " + idt);
                }
            }

            if(claims.containsKey("code")) {
                if(idt.getCHash() == null) {
                    throw new MissingRequiredAttribute("Missing cHash property " + idt);
                }
                Object code = claims.get("code");
                if(!(code instanceof String)) {
                    throw new IllegalArgumentException("code should be of type String");
                }
                String codeString = (String) code;
                if(!idt.getCHash().equals(JWS.leftHash(codeString, hashFunction))) {
                    throw new CHashError("Failed to verify code hash " + idt);
                }
            }

            claims.put("verifiedIdToken", idt);
            addDict(claims);
        }
        return true;
    }
}
