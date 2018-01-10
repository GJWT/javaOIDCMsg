package oiccli.service;

import oiccli.client_info.ClientInfo;
import oiccli.exceptions.ConfigurationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class ProviderInfoDiscovery extends service.ProviderInfoDiscovery {
    private Message message;
    private ProviderConfigurationResponse providerConfigurationResponse;
    private ErrorResponse errorResponse;
    private final static Logger logger = LoggerFactory.getLogger(ProviderInfoDiscovery.class);

    public ProviderInfoDiscovery(String httpLib, KeyJar keyJar, String clientAuthenticationMethod) {
        super(httpLib, keyJar, clientAuthenticationMethod);
        this.postParseResponse.insert(0, this.oicPostParseResponse);
    }

    public void oicPostParseResponse(String response, ClientInfo clientInfo) {
        this.matchPreferences(clientInfo, response, clientInfo.getIssuer());
    }

    public static void matchPreferences(ClientInfo clientInfo, Map<String, List<String>> pcr) throws ConfigurationError {
        if (pcr == null) {
            pcr = clientInfo.getProviderInfo();
        }

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
                String vtype = rr.getCParam().get(key);
                for (String valueIndex : values) {
                    if (listOfValues.contains(valueIndex)) {
                        Map<String, List<String>> behavior = clientInfo.getBehavior();
                        behavior.put(key, Arrays.asList(value));
                        clientInfo.setBehavior(behavior);
                    }
                }
            }

            if (!clientInfo.getBehavior().containsKey(key)) {
                throw new ConfigurationError("OP couldn't match preferences " + key);
            }
        }

        /*

        STARTED WITH JAVA CODE

        set = clientInfo.getClientPrefs().entrySet();
        iterator = set.iterator();
        while (iterator.hasNext()) {
            mapEntry = (Map.Entry) iterator.next();
            key = (String) mapEntry.getKey();
            value = (String) mapEntry.getValue();

            if(clientInfo.getBehavior().containsKey(key)) {
                continue;
            }

            value = value.g


        }
        ---------------
        THIS IS THE PYTHON CODE

                for key, val in cli_info.client_prefs.items():
            if key in cli_info.behaviour:
                continue

            try:
                vtyp = regreq.c_param[key]
                if isinstance(vtyp[0], list):
                    pass
                elif isinstance(val, list) and not isinstance(val,
                                                              six.string_types):
                    val = val[0]
            except KeyError:
                pass
            if key not in PREFERENCE2PROVIDER:
                cli_info.behaviour[key] = val*/

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
