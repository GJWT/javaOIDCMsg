package com.auth0.jwt.oiccli.Utils;

import com.auth0.jwt.oiccli.Database;
import com.auth0.jwt.oiccli.State;
import com.auth0.jwt.oiccli.exceptions.ValueError;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.LoggerFactory;

public class ClientInfo {

    private static final String ALG = "alg";
    private static final String ENC = "enc";
    private static final String SIGN = "sign";
    private static final String RS256 = "RS256";
    private static final String HS256 = "HS256";
    private static final String SHA_256 = "SHA-256";
    private static final Map<String, String> userInfoMap =
            ImmutableMap.of(SIGN, "userinfoSignedResponseAlg",
                    ALG, "userinfoEncryptedResponseAlg",
                    ENC, "userinfoEncryptedResponseEnc");
    private static final Map<String, String> idTokenMap =
            ImmutableMap.of(SIGN, "idTokenSignedResponseAlg",
                    ALG, "idTokenEncryptedResponseAlg",
                    ENC, "idTokenEncryptedResponseEnc");
    private static final Map<String, String> requestMap =
            ImmutableMap.of(SIGN, "requestObjectSigningAlg",
                    ALG, "requestObjectEncryptionAlg",
                    ENC, "requestObjectEncryptionEnc");
    private static final Map<String, Map<String, String>> ATTRIBUTE_MAP =
            ImmutableMap.of("userinfo", userInfoMap, "idToken", idTokenMap, "request", requestMap);
    private static final Map<String, String> DEF_SIGN_ALG =
            ImmutableMap.of("idToken", RS256,
                    "userInfo", RS256,
                    "requestObject", RS256,
                    "clientSecretJwt", HS256,
                    "privateKeyJwt", RS256);
    private String baseUrl;
    private String requestsDir;
    private String cId;
    private String cSecret;
    private String issuer;
    private List<String> redirectUris;
    private Map<String, List<String>> clientPrefs;
    private Map<String, String> allow;
    Map<String,List<String>> behavior;
    private KeyJar keyJar;
    private State stateDB;
    private boolean shouldBeStrictOnPreferences;
    private Map<String, List<String>> providerInfo;
    private Map<String, List<String>> registrationResponse;
    private Map<String, Map<String, String>> kid;
    private List<String> events;
    private Map<String, Map<String, Object>> config;
    final private static org.slf4j.Logger logger = LoggerFactory.getLogger(ClientInfo.class);

    public ClientInfo(KeyJar keyJar, Map<String, Map<String, Object>> config, List<String> events,
                      Database db, String dbName, boolean shouldBeStrictOnPreferences, Map<String,Object> args) throws NoSuchFieldException, IllegalAccessException {
        if(keyJar != null) {
            this.keyJar = keyJar;
        } else {
            this.keyJar = new KeyJar();
        }
        this.stateDB = new State("", db, dbName);
        this.events = events;
        this.shouldBeStrictOnPreferences = shouldBeStrictOnPreferences;
        this.providerInfo = new HashMap<>();
        this.registrationResponse = new HashMap<>();
        this.kid = new HashMap() {{
            put("sig", new HashMap<>());
            put(ENC, new HashMap<>());
        }};
        if(config == null) {
            this.config = new HashMap<>();
        } else {
            this.config = config;
        }
        this.baseUrl = "";
        this.requestsDir = "";
        this.allow = new HashMap<>();
        this.behavior = new HashMap<>();
        this.clientPrefs = new HashMap<>();
        this.cId = "";
        this.cSecret = "";
        this.issuer = "";

        for (String key : args.keySet()) {
            this.getClass().getField(key).set(key, args.get(key));
        }

        List<String> attributes = new ArrayList<>(Arrays.asList("clientId", "issuer", "clientSecret", "baseUrl", "requestsDir"));
        Map<String, Object> value;
        for (String attribute : attributes) {
            value = config.get(attribute);
            if (value != null) {
                this.getClass().getField(attribute).set(attribute, value);
            } else {
                this.getClass().getField(attribute).set(attribute, "");
            }
        }

        attributes = new ArrayList<>(Arrays.asList("allow", "clientPrefs", "behavior", "providerInfo"));
        for (String attribute : attributes) {
            value = config.get(attribute);
            if (value != null) {
                this.getClass().getField(attribute).set(attribute, value);
            } else {
                this.getClass().getField(attribute).set(attribute, new HashMap<>());
            }
        }

        if (!Strings.isNullOrEmpty(requestsDir)) {
            File file = new File(requestsDir);
            if (!file.isDirectory()) {
                try {
                    file.mkdir();
                } catch (SecurityException se) {
                    throw new SecurityException("Directory " + requestsDir + " was not created");
                }
            }
        }

        Map<String, Object> redirectUris = config.get("redirectUris");
        if (redirectUris != null) {
            this.redirectUris = redirectUris;
        } else {
            this.redirectUris = null;
        }

        this.importKeys(config.get("keys"));

        if (config.containsKey("keydefs")) {
            //oicmsg
            this.keyJar = buildKeyJar(config.get("keydefs"), this.keyJar)[1];
        }
    }

    //client_secret = property(get_client_secret, set_client_secret)

    public String getClientSecret() {
        return cSecret;
    }

    public void setClientSecret(String cSecret) {
        if(Strings.isNullOrEmpty(cSecret)) {
            this.cSecret = "";
        } else {
            this.cSecret = cSecret;
            if(this.keyJar == null) {
                this.keyJar = new KeyJar();
            }
            this.keyJar.addSymmetric("", cSecret);
        }
    }

    public String getClientId() {
        return this.cId;
    }

    public void setClientId(String clientId) {
        this.cId = clientId;
        this.stateDB.setClientId(clientId);
    }

    //client_id = property(get_client_id, set_client_id)

    public String filenameFromWebname(String webName) throws ValueError {
        if(!webName.startsWith(this.baseUrl)) {
            throw new ValueError("Webname doesn't match baseUrl");
        }
        webName = webName.substring(baseUrl.length());
        if (webName.startsWith("/")) {
            return webName.substring(1);
        } else {
            return webName;
        }
    }

    public Map<String, List<String>> signEncAlgs(String type) {
        Map<String, List<String>> response = new HashMap<>();
        List<String> value;
        for (String key : ATTRIBUTE_MAP.get(type).keySet()) {
            value = this.registrationResponse.get(ATTRIBUTE_MAP.get(key));
            if (ATTRIBUTE_MAP.get(key) != null && value != null) {
                response.put(key, value);
            } else {
                if (key.equals(SIGN)) {
                    response.put(key, Arrays.asList(DEF_SIGN_ALG.get(type)));
                }
            }
        }

        return response;
    }

    public boolean verifyAlgSupport(String algorithm, String usage, String type) {
        List<String> supported = this.providerInfo.get(usage + type + "valuesSupported");
        return supported.contains(algorithm);
    }

    public List<String> generateRequestUris(String requestsDir) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(SHA_256);
        List<String> providerInfoList = this.providerInfo.get("issuer");
        if(providerInfoList != null && !providerInfoList.isEmpty()) {
            String providerInfo = providerInfoList.get(0);
            if(!Strings.isNullOrEmpty(providerInfo)) {
                digest.update(providerInfo.getBytes());
            }
        } else {
            digest.update(this.issuer.getBytes());
        }

        digest.update(this.baseUrl.getBytes());

        if(!requestsDir.startsWith("/")) {
            return Arrays.asList(this.baseUrl + "/" + requestsDir + "/" + digest.digest());
        } else {
            return Arrays.asList(this.baseUrl + requestsDir + "/" + digest.digest());
        }
    }

    public void importKeys(Map<String, Map<String, List<String>>> keySpec) {
        for (String key : keySpec.keySet()) {
            if (key.equals("file")) {
                Map<String, List<String>> hMap = keySpec.get(key);
                for (String hMapKey : hMap.keySet()) {
                    if (hMapKey.equals("rsa")) {
                        Key key;
                        KeyBundle keyBundle;
                        for (String file : hMap.get(hMapKey)) {
                            //TODO: importPrivateRsaKeyFromFile is from cryptojwt
                            key = new RSAKey(importPrivateRsaKeyFromFile(file), "sig");
                            keyBundle = new KeyBundle();
                            keyBundle.append(key);
                            this.keyJar.addKb("", keyBundle);
                        }
                    }
                }
            } else if (key.equals("url")) {
                KeyBundle keyBundle;
                for (String issuer : keySpec.keySet()) {
                    keyBundle = new KeyBundle(keySpec.get(issuer));
                    this.keyJar.addKb(keyBundle);
                }
            }
        }
    }

    public State getStateDb() {
        return this.stateDB;
    }

    public Map<String, Map<String, Object>> getConfig() {
        return config;
    }

    public Map<String,List<String>> getBehavior() {
        return behavior;
    }

    public KeyJar getKeyJar() {
        return keyJar;
    }

    public Map<String, List<String>> getRegistrationResponse() {
        return registrationResponse;
    }

    public Map<String,List<String>> getProviderInfo() {
        return providerInfo;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuer() {
        return issuer;
    }

    public Map<String, List<String>> getClientPrefs() {
        return clientPrefs;
    }

    public boolean getShouldBeStrictOnPreferences() {
        return shouldBeStrictOnPreferences;
    }

    public void setBehavior(Map<String,List<String>> behavior) {
        this.behavior = behavior;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public String getRequestsDir() {
        return requestsDir;
    }

    public void setRegistrationResponse(Map<String, List<String>> registrationResponse) {
        this.registrationResponse = registrationResponse;
    }
}
