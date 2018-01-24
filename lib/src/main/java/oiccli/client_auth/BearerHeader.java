package oiccli.client_auth;

import oiccli.client_info.ClientInfo;

import java.util.HashMap;
import java.util.Map;

public class BearerHeader {

    public Map<String, Map<String, String>> construct(Map<String, String> cis, ClientInfo clientInfo, Map<String, String> requestArgs, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) {
        String accessToken;
        if (cis != null) {
            if (cis.containsKey("accessToken")) {
                accessToken = cis.get("accessToken");
                cis.remove(accessToken);
                //cis.c_param["access_token"] = SINGLE_OPTIONAL_STRING
            } else {
                accessToken = requestArgs.get("accessToken");
                requestArgs.remove(accessToken);

                if (accessToken != null) {
                    accessToken = args.get("accessToken");
                    if (accessToken == null) {
                        accessToken = clientInfo.getStateDb().getTokenInfo(args).get("accessToken");
                    }
                }
            }
        } else {
            accessToken = args.get("accessToken");
            if (accessToken == null) {
                accessToken = requestArgs.get("accessToken");
            }
        }

        String bearer = "Bearer " + accessToken;
        if (httpArgs == null) {
            Map<String, String> hMap = new HashMap<>();
            hMap.put("Authorization", bearer);
            httpArgs.put("headers", hMap);
        } else {
            Map<String, String> hMap = httpArgs.get("headers");
            if (hMap == null) {
                hMap = new HashMap<>();
            }
            hMap.put("Authorization", bearer);
            httpArgs.put("headers", hMap);
        }

        return httpArgs;
    }
}
