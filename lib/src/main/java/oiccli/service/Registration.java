package oiccli.service;

import com.google.common.base.Strings;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import oiccli.client_info.ClientInfo;

public class Registration extends Service {

    private RegistrationRequest registrationRequest;
    private RegistrationResponse registrationResponse;
    private ErrorResponse errorResponse;
    private static String endpointName = "registrationEndpoint";
    private static boolean isSynchronous = true;
    private static String request = "registration";
    private static String bodyType = "json";
    private static String httpMethod = "POST";

    public Registration(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        /*
                self.pre_construct = [self.oic_pre_construct]
        self.post_parse_response.append(self.oic_post_parse_response)
         */
    }

    public List<Map<String, List<String>>> oicPreConstruct(ClientInfo clientInfo, Map<String, List<String>> requestArgs) {
        for (String key : this.registrationRequest.getCParam().keySet()) {
            if (!requestArgs.containsKey(key)) {
                requestArgs.put(key, clientInfo.getBehavior().get(key));
            }
        }

        if (!requestArgs.containsKey("postLogoutRedirectUris")) {
            requestArgs.put("postLogoutRedirectUris", clientInfo.getPostLogoutRedirectUris());
        }

        if (!requestArgs.containsKey("redirectUris")) {
            requestArgs.put("redirectUris", clientInfo.getRedirectUris());
        }

        if (!Strings.isNullOrEmpty(clientInfo.getProviderInfo().get("requireRequestUriRegistration").get(0))) {
            requestArgs.put("requestUris", clientInfo.generateRequestUris(clientInfo.getRequestsDir()));
        }

        return Arrays.asList(requestArgs, new HashMap<String, List<String>>());
    }

    public void oicPostParseResponse(Map<String, List<String>> response, ClientInfo cliInfo) {
        cliInfo.setRegistrationResponse(response);
        if (!cliInfo.getRegistrationResponse().containsKey("tokenEndpointAuthMethod")) {
            Map<String, List<String>> hMap = cliInfo.getRegistrationResponse();
            hMap.put("tokenEndpointAuthMethod", Arrays.asList("clientSecretBasic"));
            cliInfo.setRegistrationResponse(hMap);
        }

        cliInfo.setClientId(response.get("clientId").get(0));
        cliInfo.setClientSecret(response.get("clientSecret").get(0));
        cliInfo.setRegistrationExpires(response.get("clientSecretExpiresAt").get(0));
        cliInfo.setRegistrationAccessToken(response.get("registrationAccessToken").get(0));
    }
}
