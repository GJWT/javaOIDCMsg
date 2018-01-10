package oiccli.service;

import com.auth0.jwt.creators.Message;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.MissingParameter;

import java.util.*;

public class UserInfo extends Service {
    private Message message;
    private OpenIDSchema openIDSchema;
    private UserInfoErrorResponse userInfoErrorResponse;
    private static String endpointName = "userInfoEndpoint";
    private static boolean isSynchronous = true;
    private String request = "userInfo";
    private String defaultAuthenticationMethod = "bearerHeader";
    private String httpMethod = "POST";

    public UserInfo(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        /*
        self.pre_construct = [self.oic_pre_construct]
        self.post_parse_response.insert(0, self.oic_post_parse_response)
         */
    }

    public List<Map<String, String>> oicPreConstruct(ClientInfo clientInfo, Map<String, String> requestArgs, Map<String, Object> args) {
        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        if (!requestArgs.containsKey("accessToken")) {
            //_tinfo = cli_info.state_db.get_token_info(**kwargs)
            requestArgs.put("accessToken", tInfo.get("accessToken"));
        }

        return Arrays.asList(requestArgs, new HashMap<String, String>());
    }

    /*
        def oic_post_parse_response(self, resp, client_info, **kwargs):
        resp = self.unpack_aggregated_claims(resp, client_info)
        return self.fetch_distributed_claims(resp, client_info)
     */

    public Map<String, Map<String, String>> unpackAggregatedClaims(Map<String, Map<String, String>> userInfo, ClientInfo clientInfo) {
        Map<String, String> csrc = userInfo.get("claimSources");
        Set set = csrc.entrySet();
        Iterator iterator = set.iterator();
        Map.Entry mapEntry, mapEntryInner;
        String key, keyInner;
        Map<String, String> value, valueInner;
        while (iterator.hasNext()) {
            mapEntry = (Map.Entry) iterator.next();
            key = (String) mapEntry.getKey();
            value = (Map<String, String>) mapEntry.getValue();
            if (value.containsKey("JWT")) {
                Map<String, Object> aggregatedClaims = new Message().fromJWT(value.get("JWT"), clientInfo.getKeyJar());
                Map<String, String> cName = userInfo.get("claimNames");
                set = cName.entrySet();
                iterator = set.iterator();
                List<String> claims = new ArrayList<>();
                while (iterator.hasNext()) {
                    mapEntryInner = (Map.Entry) iterator.next();
                    keyInner = (String) mapEntryInner.getKey();
                    valueInner = (Map<String, String>) mapEntryInner.getValue();
                    /*if(valueInner)


                     */
                }
            }
        }

        return userInfo;
    }

    public Map<String, Map<String, String>> fetchDistributedClaims(Map<String, Map<String, String>> userInfo, ClientInfo clientInfo, Object callBack) {
        Map<String, String> csrc = userInfo.get("claimSources");
        Set set = csrc.entrySet();
        Iterator iterator = set.iterator();
        Map.Entry mapEntry, mapEntryInner;
        String key, keyInner;
        Map<String, String> value, valueInner;
        while (iterator.hasNext()) {
            mapEntry = (Map.Entry) iterator.next();
            key = (String) mapEntry.getKey();
            value = (Map<String, String>) mapEntry.getValue();
            if (value.containsKey("endpoint")) {
                if (value.containsKey("accessToken")) {
                    /*
                            _uinfo = self.service_request(
                            spec["endpoint"], method='GET',
                            token=spec["access_token"], client_info=cli_info)
                     */
                } else {
                    if (callBack != null) {
                        /*_uinfo = self.service_request(
                                spec["endpoint"],
                                method='GET',
                                token=callback(spec['endpoint']),
                                client_info=cli_info)*/
                    } else {
                        /*
                                _uinfo = self.service_request(
                                spec["endpoint"],
                                method='GET',
                                client_info=cli_info)
                         */
                    }
                }

                /*
                claims = [value for value, src in
                              userinfo["_claim_names"].items() if src == csrc]
                 */


            }
        }
    }

    public static Map<String, String> setIdToken(ClientInfo cliInfo, Map<String, String> requestArgs, Map<String, String> args) {
        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        String property = args.get("prop");
        if (property == null) {
            property = "idToken";
        }

        if (!requestArgs.containsKey(property)) {
            String idToken;
            try {
                String state = getState(requestArgs, args);
                idToken = cliInfo.getStateDb().getIdToken(state);
                if (idToken == null) {
                    throw new MissingParameter("No valid id token available");
                }
                requestArgs.put(property, idToken);
            } catch (MissingParameter missingParameter) {
                missingParameter.printStackTrace();
            }
        }

        return requestArgs;
    }

    public static String getState(Map<String, String> requestArgs, Map<String, String> args) throws MissingParameter {
        String state = args.get("state");
        if (state == null) {
            state = requestArgs.get("state");
            if (state == null) {
                throw new MissingParameter("state");
            }
        }

        return state;
    }

}
