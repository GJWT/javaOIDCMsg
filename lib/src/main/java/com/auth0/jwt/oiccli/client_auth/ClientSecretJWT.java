package com.auth0.jwt.oiccli.client_auth;

import com.auth0.jwt.oiccli.StringUtil;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.AuthenticationFailure;
import java.security.Key;
import java.util.Map;

public class ClientSecretJWT {

    public static String chooseAlgorithm(String entity, Map<String, String> args) throws AuthenticationFailure {
        return JWSAuthenticationMethod.chooseAlgorithm(entity, args);
    }

    public static String chooseAlgorithm(Map<String, String> args) throws AuthenticationFailure {
        return JWSAuthenticationMethod.chooseAlgorithm("clientSecretJwt", args);
    }

    @Override
    public Key getSigningKey(String algorithm, ClientInfo clientInfo) {
        return clientInfo.getKeyJar().getSigningKey(StringUtil.alg2keytype(algorithm), algorithm);
    }
}
