package oiccli.client_auth;

import oiccli.exceptions.AuthenticationFailure;

import java.util.HashMap;
import java.util.Map;

public class BearerBody {

    public Map<String, Map<String, String>> construct(Map<String, String> cis, CliInfo cliInfo, Map<String, String> requestArgs, Map<String, Map<String, String>> httpArgs,
                                                      Map<String, String> args) throws AuthenticationFailure {
        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        if (!cis.containsKey("accessToken")) {
            String accessToken = requestArgs.get("accessToken");
            if (accessToken != null) {
                cis.put("accessToken", accessToken);
            } else {
                if (args.get("state") == null) {
                    String state = cliInfo.getState();
                    if (state == null) {
                        throw new AuthenticationFailure("Missing state specification");
                    }

                    args.put("state", state);
                }

                cis.put("accessToken", cliInfo.getStateDb().getTokenInfo(args).get("accessToken"));
            }
        }

        return httpArgs;
    }
}
