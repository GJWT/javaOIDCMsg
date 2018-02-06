package com.auth0.jwt.oiccli.service;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.Service;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.MissingParameter;
import com.auth0.jwt.oiccli.responses.ErrorResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CheckSession extends Service {
    private static CheckSessionRequest checkSessionRequest;
    private static Message message;
    private static ErrorResponse errorResponse;
    private static String endpointName = "";
    private static boolean isSynchronous = true;
    private static String request = "checkSession";

    public CheckSession(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String,String> conf) throws NoSuchFieldException, IllegalAccessException {
        super(httpLib, keyJar, clientAuthenticationMethod, conf);
        this.preConstruct = Arrays.asList(oicPreConstruct);
    }

    public List<Map<String, String>> oicPreConstruct(ClientInfo clientInfo, Map<String, String> requestArgs, Map<String, String> args) throws MissingParameter {
        requestArgs = UserInfo.setIdToken(clientInfo, requestArgs, args);
        return Arrays.asList(requestArgs, new HashMap<String, String>());
    }

}