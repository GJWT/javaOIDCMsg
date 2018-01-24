package oiccli.service;

import com.auth0.jwt.creators.Message;
import oiccli.client_info.ClientInfo;
import oiccli.exceptions.MissingParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class UserInfo extends Service {
    private Message message;
    private OpenIDSchema openIDSchema;
    private UserInfoErrorResponse userInfoErrorResponse;
    private static String endpointName = "userInfoEndpoint";
    private static boolean isSynchronous = true;
    private static String request = "userInfo";
    private static String defaultAuthenticationMethod = "bearerHeader";
    private static String httpMethod = "GET";
    private final static Logger logger = LoggerFactory.getLogger(UserInfo.class);

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

    public Map<String, Map<String, String>> oicPostParseResponse(Map<String, Map<String, String>> userInfo, ClientInfo clientInfo) {
        Map<String, Map<String, String>> unpacked = this.unpackAggregatedClaims(userInfo, clientInfo);
        return this.fetchDistributedClaims(unpacked, clientInfo, null);
    }

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
                Map<String, Map<String, String>> aggregatedClaims = new Message().fromJWT(value.get("JWT"), clientInfo.getKeyJar());
                Map<String, String> cName = userInfo.get("claimNames");
                set = cName.entrySet();
                iterator = set.iterator();
                List<String> claims = new ArrayList<>();
                while (iterator.hasNext()) {
                    mapEntryInner = (Map.Entry) iterator.next();
                    keyInner = (String) mapEntryInner.getKey();
                    valueInner = (Map<String, String>) mapEntryInner.getValue();
                    if (valueInner.equals(value)) {
                        claims.add(keyInner);
                    }
                }

                for (String claim : claims) {
                    userInfo.put(claim, aggregatedClaims.get(claim));
                }
            }
        }

        return userInfo;
    }

    public Map<String, Map<String, String>> fetchDistributedClaims(Map<String, Map<String, String>> userInfo, ClientInfo clientInfo, Method callBack) {
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
            ErrorResponse errorResponse;
            if (value.containsKey("endpoint")) {
                if (value.containsKey("accessToken")) {
                    //TODO:callback is a method; figure out how to pass a method as a param to a function
                    errorResponse = oiccli.Service.serviceRequest(value.get("endpoint"), "GET", value.get("accessToken"), clientInfo);
                } else {
                    if (callBack != null) {
                        errorResponse = oiccli.Service.serviceRequest(value.get("endpoint"), "GET", callBack(value.get("endpoint")), clientInfo);
                    } else {
                        errorResponse = oiccli.Service.serviceRequest(value.get("endpoint"), "GET", clientInfo);
                    }
                }

                List<String> claims = new ArrayList<>();
                Set<String> keys = userInfo.get("claimNames").keySet();
                String valueIndex;
                for (String keyIndex : keys) {
                    valueIndex = userInfo.get("claimNames").get(keyIndex);
                    if (valueIndex.equals(key)) {
                        claims.add(valueIndex);
                    }
                }

                if (new HashSet<>(claims).equals(new HashSet<>(errorResponse.getKeys()))) {
                    logger.warn("Claims from claim source doesn't match what's in the userinfo");
                }

                for (String errorResponseKey : errorResponse.keySet()) {
                    userInfo.put(errorResponseKey, errorResponse.get(errorResponseKey));
                }
            }
        }
        return userInfo;
    }

    public static Map<String, String> setIdToken(ClientInfo cliInfo, Map<String, String> requestArgs, Map<String, String> args) throws MissingParameter {
        if (requestArgs == null) {
            requestArgs = new HashMap<>();
        }

        String property = args.get("prop");
        if (property == null) {
            property = "idToken";
        }

        if (!requestArgs.containsKey(property)) {
            String idToken;
            String state = getState(requestArgs, args);
            idToken = cliInfo.getStateDb().getIdToken(state);
            if (idToken == null) {
                throw new MissingParameter("No valid id token available");
            }
            requestArgs.put(property, idToken);
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
