package oiccli.client_auth;

import oiccli.StringUtil;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.AuthenticationFailure;

import java.security.Key;
import java.util.Map;

public class ClientSecretJwt extends JWSAuthenticationMethod {

    public static String chooseAlgorithm(String entity, Map<String, String> args) throws AuthenticationFailure {
        return JWSAuthenticationMethod.chooseAlgorithm(entity, args);
    }

    public Key getSigningKey(String algorithm, ClientInfo clientInfo) {
        return clientInfo.getKeyJar().getSigningKey(StringUtil.alg2keytype(algorithm), algorithm);
    }
}
