package oiccli.client_info;

import com.google.common.collect.ImmutableMap;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import oiccli.State;
import oiccli.StringUtil;
import oiccli.exceptions.ExpiredToken;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;

public class ClientInfo {

    private static final Map<String, String> userInfoMap =
            ImmutableMap.of("sign", "userinfoSignedResponseAlg",
                    "alg", "userinfoEncryptedResponseAlg",
                    "enc", "userinfoEncryptedResponseEnc");
    private static final Map<String, String> idTokenMap =
            ImmutableMap.of("sign", "idTokenSignedResponseAlg",
                    "alg", "idTokenEncryptedResponseAlg",
                    "enc", "idTokenEncryptedResponseEnc");
    private static final Map<String, String> requestMap =
            ImmutableMap.of("sign", "requestObjectSigningAlg",
                    "alg", "requestObjectEncryptionAlg",
                    "enc", "requestObjectEncryptionEnc");
    private static final Map<String, Map<String, String>> attributeMap =
            ImmutableMap.of("userinfo", userInfoMap, "idToken", idTokenMap, "request", requestMap);
    private static final Map<String, String> defSignAlg =
            ImmutableMap.of("idToken", "RS256",
                    "userInfo", "RS256",
                    "requestObject", "RS256",
                    "clientSecretJwt", "HS256",
                    "privateKeyJwt", "RS256");

    private KeyJar keyJar;
    private State stateDb;
    private List<String> events;
    private boolean shouldBeStrictOnPreferences;
    private Map<String, List<String>> providerInfo;
    private Map<String, String> registrationResponse;
    private String registrationExpires;
    private String registrationAccessToken;
    private Map<String, Map<String, String>> kid;
    private Map<String, Map<String, Object>> config;
    private Map<String, String> allow;
    private Map<String, List<String>> behavior;
    private Map<String, List<String>> clientPrefs;
    private String baseUrl;
    private String requestsDir;
    private String cId;
    private String cSecret;
    private String issuer;
    private String redirectUris;
    final private static Logger logger = LoggerFactory.getLogger(ClientInfo.class);

    public ClientInfo(KeyJar keyjar, Map<String, String> config, List<String> events,
                      Database db, String dbName, boolean shouldBeStrictOnPreferences,
                      Map<String, Object> args) throws NoSuchFieldException, IllegalAccessException {
        this.keyJar = keyjar;
        this.stateDb = new State(" ", db, dbName);
        this.events = events;
        this.shouldBeStrictOnPreferences = shouldBeStrictOnPreferences;
        this.providerInfo = new HashMap<>();
        this.registrationResponse = new HashMap<>();
        this.kid = new HashMap() {{
            put("sig", new HashMap<>());
            put("enc", new HashMap<>());
        }};
        this.config = config;
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

            /*if (attribute.equals("clientId")) {
                this.stateDb.setClientId(config.get(attribute));
            }*/
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

        if (StringUtil.isNotNullAndNotEmpty(requestsDir)) {
            File file = new File(requestsDir);
            if (!file.isDirectory()) {
                try {
                    file.mkdir();
                } catch (SecurityException se) {
                    logger.error("Directory " + requestsDir + " was not created");
                }
            }
        }

        String redirectUris = config.get("redirectUris");
        if (redirectUris != null) {
            this.redirectUris = redirectUris;
        } else {
            this.redirectUris = null;
        }

        this.importKeys(config.get("keys"));

        if(config.containsKey("keydefs")) {
            this.keyJar = buildKeyJar(config.get("keydefs"), this.keyJar)[1];
        }
    }

    public void importKeys(Map<String,Map<String,List<String>>> keySpec) {
        for(String key : keySpec.keySet()) {
            if(key.equals("file")) {
                Map<String,List<String>> hMap = keySpec.get(key);
                for(String hMapKey : hMap.keySet()) {
                    if(hMapKey.equals("rsa")) {
                        Key key;
                        KeyBundle keyBundle;
                        for(String file : hMap.get(hMapKey)) {
                            key = new RSAKey(importPrivateRsaKeyFromFile(file), "sig");
                            keyBundle = new KeyBundle();
                            keyBundle.append(key);
                            this.keyJar.addKb("", keyBundle);
                        }
                    }
                }
            } else if(key.equals("url")) {
                KeyBundle keyBundle;
                for(String issuer : keySpec.keySet()) {
                    keyBundle = new KeyBundle(keySpec.get(issuer));
                    this.keyJar.addKb(keyBundle);
                }
            }
        }
    }

    public String getCSecret() {
        return this.cSecret;
    }

    public String getIssuer() {
        return issuer;
    }

    public Map<String, List<String>> getProviderInfo() {
        return providerInfo;
    }

    public Map<String, List<String>> getClientPrefs() {
        return clientPrefs;
    }

    public boolean getShouldBeStrictOnPreferences() {
        return shouldBeStrictOnPreferences;
    }

    public Map<String, List<String>> getBehavior() {
        return behavior;
    }

    public void setBehavior(Map<String, List<String>> behavior) {
        this.behavior = behavior;
    }

    public String getRequestsDir() {
        return requestsDir;
    }

    public String getClientSecret() {
        return cSecret;
    }

    public Map<String, Map<String, String>> getKid() { return kid; }

    public void setClientSecret(String cSecret) {
        this.cSecret = cSecret;
    }

    public State getState() { return stateDb; }

    public void setCSecret(String secret) {
        if (secret == null) {
            this.cSecret = "";
        } else {
            this.cSecret = secret;
            if (this.keyJar == null) {
                this.keyJar = new KeyJar();
            }

            this.keyjar.addSymmetric("", secret);
        }
    }

    //client_secret = property(get_client_secret, set_client_secret)

    public String getClientId() {
        return this.cId;
    }

    public void setClientId(String clientId) {
        this.cId = clientId;
        this.stateDb.setClientId(clientId);
    }

    public void setRegistrationResponse(Map<String, String> registrationResponse) {
        this.registrationResponse = registrationResponse;
    }

    public Map<String, String> getRegistrationResponse() {
        return this.registrationResponse;
    }

    public String getRegistrationExpires() {
        return registrationExpires;
    }

    public String getRegistrationAccessToken() {
        return registrationAccessToken;
    }

    public void setRegistrationAccessToken(String registrationAccessToken) {
        this.registrationAccessToken = registrationAccessToken;
    }

    public KeyJar getKeyJar() {
        return keyJar;
    }

    public State getStateDb() {
        return stateDb;
    }

    public void setStateDb(State stateDb) {
        this.stateDb = stateDb;
    }

    //client_id = property(get_client_id, set_client_id)

    public void setItem(String key, String value) throws NoSuchFieldException, IllegalAccessException {
        this.getClass().getField(key).set(key, value);
    }

    public String filenameFromWebname(String webName) {
        Assert.assertTrue(webName.startsWith(this.baseUrl));
        webName = webName.substring(baseUrl.length());
        if (webName.startsWith("/")) {
            return webName.substring(1);
        } else {
            return webName;
        }
    }

    public Map<String, String> signEncAlgs(SignEncAlgs type) {
        Map<String, String> response = new HashMap<>();
        String value;
        for (String key : attributeMap.get(type).keySet()) {
            value = this.registrationResponse.get(attributeMap.get(key));
            if (attributeMap.get(key) != null && value != null) {
                response.put(key, value);
            } else {
                if (key.equals("sign")) {
                    response.put(key, defSignAlg.get(type));
                }
            }
        }

        return response;
    }

    public boolean verifyAlgSupport(String algorithm, VerifyAlgSupportUsage usage, VerifyAlgSupportType type) {
        List<String> supported = this.providerInfo.get(usage + "" + type + "valuesSupported");
        return supported.contains(algorithm);
    }

    public List<String> generateRequestUris(String requestsDir) {
        //m = hashlib.sha256()
        String issuer = this.providerInfo.get("issuer");
        if (issuer != null) {
            m.update(issuer.getBytes());
        } else {
            m.update(this.issuer);
        }
        m.update(this.baseUrl.getBytes());

        return this.baseUrl + requestsDir + "/" + m.hexDigest();
    }

    public static List<Object> addCodeChallenge(ClientInfo clientInfo, String state) {
        Integer cvLength = (Integer) clientInfo.config.get("codeChallenge").get("length");
        if(cvLength == null) {
            cvLength = 64;
        }

        String codeVerifier = StringUtil.generateRandomString(cvLength);
        codeVerifier = Base64.encode(codeVerifier.getBytes());

        String method = (String) clientInfo.config.get("codeChallenge").get("method");
        if (method == null) {
            method = "S256";
        }

        /*
            try:
        _h = CC_METHOD[_method](_cv).hexdigest()
        code_challenge = b64e(_h.encode()).decode()
    except KeyError:
        raise Unsupported(
            'PKCE Transformation method:{}'.format(_method))
         */

        clientInfo.getStateDb().addInfo(state, null);

        Map<String, String> hMap = new HashMap<>();
        hMap.put("codeChallenge", codeChallenge);
        hMap.put("codeChallengeMethod", method);

        return Arrays.asList(hMap, codeVerifier);
    }

    public void setRegistrationExpires(String registrationExpires) {
        this.registrationExpires = registrationExpires;
    }

    public static Object getCodeVerifier(ClientInfo clientInfo, String state) throws ExpiredToken {
        return clientInfo.getStateDb().getTokenInfo("state"+state).get("codeVerifier");
    }
}
