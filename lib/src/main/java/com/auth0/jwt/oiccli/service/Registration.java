package com.auth0.jwt.oiccli.service;

import com.auth0.jwt.oiccli.Service;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.MissingRequiredAttribute;
import com.auth0.jwt.oiccli.responses.ErrorResponse;
import com.google.common.base.Strings;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Registration extends Service {

    private RegistrationRequest registrationRequest; //oicmsg
    private RegistrationResponse registrationResponse; //oicmsg
    private ErrorResponse errorResponse; //oicmsg
    private static String endpointName = "registrationEndpoint";
    private static boolean isSynchronous = true;
    private static String request = "registration";
    private static String bodyType = "json";
    private static String httpMethod = "POST";

    public Registration(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String,String> conf) throws NoSuchFieldException, IllegalAccessException {
        super(httpLib, keyJar, clientAuthenticationMethod, conf);

        this.preConstruct.add(oicPreConstruct);
        this.postParseResponse.add(this.oicPostParseResponse());
    }

    public List<Map<String, List<String>>> oicPreConstruct(ClientInfo clientInfo, Map<String, List<String>> requestArgs) throws NoSuchAlgorithmException {
        for (String key : this.registrationRequest.getCParam().keySet()) {
            if (!requestArgs.containsKey(key)) {
                requestArgs.put(key, clientInfo.getBehavior().get(key));
            }
        }

        if (!requestArgs.containsKey("postLogoutRedirectUris")) {
            requestArgs.put("postLogoutRedirectUris", clientInfo.getRedirectUris());  //postLogoutRedirectUris??
        }

        if (!requestArgs.containsKey("redirectUris")) {
            List<String> redirectUris = clientInfo.getRedirectUris();
            if(redirectUris != null && !redirectUris.isEmpty()) {
                requestArgs.put("redirectUris", redirectUris);
            } else {
                throw new MissingRequiredAttribute("redirectUris is null or empty")
            }
        }

        String requestDir = clientInfo.getRequestsDir();
        if(!Strings.isNullOrEmpty(requestDir)) {
            if (!Strings.isNullOrEmpty(clientInfo.getProviderInfo().get("requireRequestUriRegistration").get(0))) {
                requestArgs.put("requestUris", clientInfo.generateRequestUris(clientInfo.getRequestsDir()));
            }
        }

        return Arrays.asList(requestArgs, new HashMap<String, List<String>>());
    }

    public void oicPostParseResponse(RegistrationResponse response, ClientInfo cliInfo) {
        cliInfo.setRegistrationResponse(response);
        if (!cliInfo.getRegistrationResponse().containsKey("tokenEndpointAuthMethod")) {
            Map<String, List<String>> hMap = cliInfo.getRegistrationResponse();
            hMap.put("tokenEndpointAuthMethod", Arrays.asList("clientSecretBasic"));
            cliInfo.setRegistrationResponse(hMap);
        }

        cliInfo.setClientId(response.getClientId().get(0));
        cliInfo.setClientSecret(response.getClientSecret().get(0));
        cliInfo.setRegistrationExpires(response.getClientSecretExpiresAt().get(0));
        cliInfo.setRegistrationAccessToken(response.getRegistrationAccessToken().get(0));
    }
}
