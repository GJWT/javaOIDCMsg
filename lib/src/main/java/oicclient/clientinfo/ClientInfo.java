package oicclient.clientinfo;

import com.google.common.base.Strings;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import oicclient.exceptions.ValueError;
import org.slf4j.LoggerFactory;

public class ClientInfo {

    private static final String ENC = "enc";
    private static final String SIG = "sig";
    private static final String SHA_256 = "SHA-256";
    private String baseUrl;
    private String requestsDir;
    private String cId;
    private String cSecret;
    private String issuer;
    private String redirectUris;
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
    private Map<String, String> config;
    final private static org.slf4j.Logger logger = LoggerFactory.getLogger(ClientInfo.class);

    public ClientInfo(KeyJar keyJar, Map<String, String> config, List<String> events,
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
            put(SIG, new HashMap<>());
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
        String value;
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
            if (!Strings.isNullOrEmpty(value)) {
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

        String redirectUris = config.get("redirectUris");
        if (!Strings.isNullOrEmpty(redirectUris)) {
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

    public void importKeys(Map<String, Map<String, List<String>>> keySpec) {
        for (String keyString : keySpec.keySet()) {
            if (keyString.equals("file")) {
                Map<String, List<String>> hMap = keySpec.get(keyString);
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
            } else if (keyString.equals("url")) {
                KeyBundle keyBundle;
                for (String issuer : keySpec.keySet()) {
                    keyBundle = new KeyBundle(keySpec.get(issuer));
                    this.keyJar.addKb(issuer, keyBundle);
                }
            }
        }
    }

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

}
