package oiccli.client_auth;

import oiccli.StringUtil;

import java.util.Map;

public class ClientSecretJwt extends JWSAuthenticationMethod {

    public String chooseAlgorithm(String entity, Map<String, String> args) {
        return JWSAuthenticationMethod.chooseAlgorithm(entity, args);
    }

    public Key getSigningKey(String algorithm, CliInfo cliInfo) {
        return cliInfo.keyjar.getSigningKey(StringUtil.alg2keytype(algorithm), algorithm);
    }
}
