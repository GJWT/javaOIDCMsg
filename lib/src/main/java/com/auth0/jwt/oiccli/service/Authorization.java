package com.auth0.jwt.oiccli.service;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.AuthorizationRequest;
import com.auth0.jwt.oiccli.AuthorizationResponse;
import com.auth0.jwt.oiccli.StringUtil;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.Utils.Utils;
import com.auth0.jwt.oiccli.exceptions.ValueError;
import com.auth0.jwt.oiccli.tuples.Tuple;
import com.google.common.base.Strings;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Authorization extends service.Authorization {

    private AuthorizationRequest authorizationRequest;  //oicmsg
    private AuthorizationResponse authorizationResponse; //oicmsg
    private AuthorizationErrorResponse authorizationErrorResponse; //oicmsg
    private Map<String, List<String>> defaultRequestArgs;
                                        //keyjar - oicmsg
    public Authorization(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String,String> conf) {
        super(httpLib, keyJar, clientAuthenticationMethod, conf);
        this.defaultRequestArgs = new HashMap() {{
            put("scope", Arrays.asList("openId"));
        }};
        this.preConstruct = Arrays.asList(oicPreConstruct);
        this.postConstruct = Arrays.asList(this.oicPostConstruct);
        this.postParseResponse.add(storeIdToken);
    }

    public List<Map<String, ?>> oicPreConstruct(ClientInfo clientInfo, Map<String, Object> requestArgs, Map<String, String> args) {
        if (requestArgs != null) {
            String responseType = (String) requestArgs.get("responseType");
            if (Strings.isNullOrEmpty(responseType)) {
                requestArgs.put("responseType", clientInfo.getBehavior().get("responseTypes").get(0));
                if (responseType.contains("token") || responseType.contains("idToken")) {
                    if (!requestArgs.containsKey("nonce")) {
                        requestArgs.put("nonce", StringUtil.generateRandomString(32));
                    }
                }
            }
        } else {
            requestArgs = new HashMap();
        }

        Map<String, String> postArgs = new HashMap<>();
        for (String attribute : Arrays.asList("requestObjectSigningAlg", "algorithm", "sigKid")) {
            postArgs.put(attribute, args.get(attribute));
            args.remove(attribute);
        }

        if (args.containsKey("requestMethod")) {
            if (args.get("requestMethod").equals("reference")) {
                postArgs.put("requestParam", "requestUri");
            } else {
                postArgs.put("requestParam", "request");
            }
            args.remove("requestMethod");
        }

        List<String> responseMode = clientInfo.getBehavior().get("responseMode");
        if (responseMode != null && !responseMode.isEmpty() && responseMode.contains("formPost")) {
            requestArgs.put("responseMode", responseMode);
        }

        clientInfo.getStateDb().createState(clientInfo.getIssuer(), requestArgs, (String) requestArgs.get("state"));

        if (!requestArgs.containsKey("state")) {
            requestArgs.put("state", clientInfo.getStateDb().createState(clientInfo.getIssuer(), requestArgs));
        }

        return Arrays.asList(requestArgs, postArgs);
    }

    public Map<String, String> oicPostConstruct(ClientInfo clientInfo, Map<String, String> req, Map<String, String> args) throws ValueError {
        //TODO: Check with Roland about this method

        String requestParam = args.get("requestParam");
        args.remove("requestParam");

        String algorithm = null;
        for (String argument : Arrays.asList("requestObjectSigningAlg", "algorithm")) {
            algorithm = args.get(argument);
        }

        if (algorithm == null) {
            algorithm = clientInfo.getBehavior().get("requestObjectSigningAlg");
            if (algorithm == null) {
                algorithm = "RS256";
            }
        }

        args.put("requestObjectSigningAlg", algorithm);

        if (!args.containsKey("keys") && algorithm != null && !algorithm.equals("none")) {
            String kty = StringUtil.alg2keytype(algorithm);
            String kid = args.get("sigKid");
            if (kid == null) {
                kid = clientInfo.getKid().get("sig").get(kty);
            }
            args.put("keys", clientInfo.getKeyJar().getSigningKey(kty, kid));
        }

        /*
            _req = make_openid_request(req, **kwargs)
        */

        Message _req = Utils.requestObjectEncryption(_req, clientInfo, args);

        String webName;
        String fileName;
        if (requestParam.equals("request")) {
            req.put("request", _req);
        } else {
            webName = clientInfo.getRegistrationResponse().get("requestUris").get(0);
            fileName = clientInfo.filenameFromWebname(webName);
            if(Strings.isNullOrEmpty(fileName)) {
                Tuple tuple = Utils.constructRequestUri(null, null, args);
                webName = (String) tuple.getA();
                fileName = (String) tuple.getB();
            }
            BufferedWriter writer = null;
            try {
                writer = new BufferedWriter(new FileWriter(fileName));
                writer.write(_req);
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            req.put("requestUri", webName);
        }

        return req;
    }
}
