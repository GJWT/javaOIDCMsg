package com.auth0.jwt.oiccli.service;

import com.auth0.jwt.creators.Message;
import com.auth0.jwt.oiccli.Utils.ClientInfo;
import com.auth0.jwt.oiccli.exceptions.ConfigurationError;
import com.auth0.jwt.oiccli.responses.ErrorResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import oiccli.service.Service;

public class ProviderInfoDiscovery extends service.ProviderInfoDiscovery {
    private Message message;
    private ProviderConfigurationResponse providerConfigurationResponse; //oicmsg
    private ErrorResponse errorResponse;
    private KeyJar keyJar;
    private final static Logger logger = LoggerFactory.getLogger(ProviderInfoDiscovery.class);

    public ProviderInfoDiscovery(String httpLib, KeyJar keyJar, String clientAuthenticationMethod, Map<String,String> conf) {
        super(httpLib, keyJar, clientAuthenticationMethod, conf);
        this.postParseResponse.insert(0, this.oicPostParseResponse);

        if(conf != null) {
            if(conf.get("preLoadKeys") != null) {
                this.postParseResponse.append(this.preLoadKeys);
            }
        }
    }

    public void oicPostParseResponse(Map<String, List<String>> response, ClientInfo clientInfo) throws ConfigurationError {
        matchPreferences(clientInfo, response, clientInfo.getIssuer());
    }
            //jwks - cryptojwt
    public Jwks preLoadKeys(Map<String, List<String>> response) {
        Jwks jwks = this.keyJar.exportJwksAsJson(response.get("issuer"));
        logger.info("Preloaded keys for " + response.get("issuer") + ": " + jwks);
        return jwks;
    }

    public static void matchPreferences(ClientInfo clientInfo, Map<String, List<String>> pcr, String issuer) throws ConfigurationError {
        if (pcr == null) {
            pcr = clientInfo.getProviderInfo();
        }
        //rr - oicmsg
        RegistrationRequest rr = new oic.RegistrationRequest();
        Set set = Service.PREFERENCE2PROVIDER.entrySet();
        Iterator iterator = set.iterator();
        Map.Entry mapEntry;
        String key, value;
        List<String> listOfValues, values;
        while (iterator.hasNext()) {
            mapEntry = (Map.Entry) iterator.next();
            key = (String) mapEntry.getKey();
            value = (String) mapEntry.getValue();
            values = clientInfo.getClientPrefs().get(key);
            listOfValues = pcr.get(value);
            if (listOfValues == null) {
                listOfValues = Arrays.asList(Service.PROVIDERDEFAULT.get(key));
            }
            if (listOfValues == null) {
                logger.info("No info from provider on " + key + " and no default.");
                if (clientInfo.getShouldBeStrictOnPreferences()) {
                    throw new ConfigurationError("OP couldn't match preferences: " + key);
                } else {
                    listOfValues = values;
                }
            }

            if (listOfValues.contains(values)) {
                setBehavior(clientInfo, key, values);
            } else {

                List<String> vTypes = rr.getCParam().get(key);
                setBehavior(clientInfo, key, new ArrayList<String>());
                for (String valueIndex : values) {
                    if (listOfValues.contains(valueIndex)) {
                        Map<String, List<String>> behavior = clientInfo.getBehavior();
                        if(behavior.get(key) != null) {
                            List<String> list = behavior.get(key);
                            list.add(valueIndex);
                            behavior.put(key, list);
                        } else {
                            behavior.put(key, Arrays.asList(valueIndex));
                        }
                        clientInfo.setBehavior(behavior);
                        break;
                    }
                }
            }

            if (!clientInfo.getBehavior().containsKey(key)) {
                throw new ConfigurationError("OP couldn't match preferences " + key);
            }
        }

        for (String keyIndex : clientInfo.getClientPrefs().keySet()) {
            if (!clientInfo.getBehavior().containsKey(keyIndex)) {
                /*
                                vtyp = regreq.c_param[key]
                if isinstance(vtyp[0], list):
                    pass
                elif isinstance(val, list) and not isinstance(val,
                                                              six.string_types):
                    val = val[0]
                 */

                if (!Service.PREFERENCE2PROVIDER.containsKey(keyIndex)) {
                    List<String> behavior = clientInfo.getBehavior().get(keyIndex);
                    if (behavior == null) {
                        behavior = new ArrayList<>();
                    }
                    behavior.addAll(clientInfo.getClientPrefs().get(keyIndex));

                    setBehavior(clientInfo, keyIndex, behavior);
                }
            }
        }

        logger.debug("cliInfo behavior " + clientInfo.getBehavior().toString());

    }

    private static void setBehavior(ClientInfo clientInfo, String key, List<String> values) {
        Map<String, List<String>> behavior = clientInfo.getBehavior();
        if (behavior.containsKey(key)) {
            List<String> returnedValue = behavior.get(key);
            returnedValue.addAll(values);
            behavior.put(key, returnedValue);
        } else {
            behavior.put(key, values);
        }
        clientInfo.setBehavior(behavior);
    }
}