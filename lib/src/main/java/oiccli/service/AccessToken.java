package oiccli.service;

import oiccli.exceptions.ParameterError;

import java.util.Arrays;
import java.util.Map;

public class AccessToken extends service.AccessToken {
    private AccessTokenRequest accessTokenRequest;
    private AccessTokenResponse accessTokenResponse;
    private TokenErrorResponse tokenErrorResponse;
    private List<> postParseResponse;

    public AccessToken(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        this.postParseResponse = Arrays.asList(this.oicPostParseResponse);
    }

    public void oicPostParseResponse(Map<String, Map<String, String>> response, CliInfo cliInfo, String state) throws ParameterError {
        Map<String, String> idt = response.get("verifiedIdToken");

        if (!cliInfo.getStateDb().nonceToState(idt.get("nonce")).equals(state)) {
            throw new ParameterError("Someone has messed with the 'nonce'");
        }
    }
}
