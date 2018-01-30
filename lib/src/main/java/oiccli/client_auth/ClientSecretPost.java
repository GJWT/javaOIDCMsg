package oiccli.client_auth;

import com.google.common.base.Strings;
import java.util.Map;
import oiccli.client_info.ClientInfo;

public class ClientSecretPost extends ClientSecretBasic {

    public Map<String, Map<String, String>> construct(AccessTokenRequest request, ClientInfo clientInfo, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) {
        if (Strings.isNullOrEmpty(request.getClientSecret())) {
            Map<String, String> clientSecret = httpArgs.get("clientSecret");
            if (clientSecret != null) {
                request.setClientSecret(clientSecret.get("clientSecret"));
                httpArgs.remove("clientSecret");
            } else {
                if (!Strings.isNullOrEmpty(clientInfo.getClientSecret())) {
                    request.setClientSecret(clientInfo.getClientSecret());
                }
            }
        }

        request.setClientId(clientInfo.getClientId());

        return httpArgs;
    }
}
