package com.auth0.jwt.oiccli.service;

import com.auth0.jwt.oiccli.AuthorizationResponse;
import com.auth0.jwt.oiccli.exceptions.ParameterError;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.UnknownState;
import com.google.common.base.Strings;
import java.util.Arrays;
import java.util.Map;

public class AccessToken extends service.AccessToken {
    private AccessTokenRequest accessTokenRequest; //oicmsg
    private AccessTokenResponse accessTokenResponse; //oicmsg
    private TokenErrorResponse tokenErrorResponse; //oicmsg
    private List<> postParseResponse;

    public AccessToken(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String,Object> conf) {
        super(httpLib, keyJar, clientAuthenticationMethod, conf);
        this.postParseResponse = Arrays.asList(this.oicPostParseResponse, storeIdToken);
    }

    public void oicPostParseResponse(AuthorizationResponse response, ClientInfo cliInfo, String state) throws ParameterError, UnknownState {
        cliInfo.getStateDb().addResponse(response, state);
        VerifiedIdToken idt = response.getVerifiedIdToken();
        String nonceToState = cliInfo.getStateDb().nonceToState(idt.getNonce());
        if (!Strings.isNullOrEmpty(nonceToState) && !nonceToState.equals(state)) {
            throw new ParameterError("Someone has messed with the 'nonce'");
        }
    }
}
