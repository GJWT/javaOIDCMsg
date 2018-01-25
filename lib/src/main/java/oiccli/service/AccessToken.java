package oiccli.service;

import java.util.Arrays;
import java.util.Map;
import oiccli.AuthorizationResponse;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.ParameterError;
import oiccli.exceptions.UnknownState;

public class AccessToken extends service.AccessToken {
    private AccessTokenRequest accessTokenRequest;
    private AccessTokenResponse accessTokenResponse;
    private TokenErrorResponse tokenErrorResponse;
    private List<> postParseResponse;

    public AccessToken(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        this.postParseResponse = Arrays.asList(this.oicPostParseResponse);
    }

    public void oicPostParseResponse(AuthorizationResponse response, ClientInfo cliInfo, String state) throws ParameterError, UnknownState {
        cliInfo.getStateDb().addResponse(response, state);
        Map<String, String> idt = response.get("verifiedIdToken");

        if (!cliInfo.getStateDb().nonceToState(idt.get("nonce")).equals(state)) {
            throw new ParameterError("Someone has messed with the 'nonce'");
        }
    }
}
