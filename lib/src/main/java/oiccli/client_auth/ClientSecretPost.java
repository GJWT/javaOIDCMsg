package oiccli.client_auth;

import java.util.Map;

public class ClientSecretPost extends ClientSecretBasic {

    public Map<String, Map<String, String>> construct(Map<String, String> cis, CliInfo cliInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) {
        if (!cis.containsKey("clientSecret")) {
            Map<String, String> clientSecret = httpArgs.get("clientSecret");
            if (clientSecret != null) {
                cis.put("clientSecret", clientSecret.get("clientSecret"));
                httpArgs.remove("clientSecret");
            } else {
                if (cliInfo.getClientSecret() != null) {
                    cis.put("clientSecret", cliInfo.getClientSecret());
                }
            }
        }

        cis.put("clientId", cliInfo.getClientId());

        return httpArgs;
    }
}
