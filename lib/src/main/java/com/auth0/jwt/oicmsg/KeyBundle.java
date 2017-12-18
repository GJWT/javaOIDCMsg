/*
package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.*;
import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.auth0.jwt.oicmsg.*;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyException;
import java.util.*;

public class KeyBundle {

    final private static Logger logger = LoggerFactory.getLogger(KeyBundle.class);
    private static final Map<String, Key> K2C =
            ImmutableMap.of("RSA", new RSAKey(),
                    "EC", new ECKey(),
                    "oct", new SYMKey()
            );
    private static final Map<String, String> map =
            ImmutableMap.of("dec", "enc",
                    "enc", "enc",
                    "ver", "sig",
                    "sig", "sig"
            );
    private List<Key> keys;
    private Map<String, List<Key>> impJwks;
    private String source;
    private long cacheTime;
    private boolean verifySSL;
    private String fileFormat;
    private String keyType;
    private List<String> keyUsage;
    private boolean remote;
    private long timeOut;
    private String eTag;
    private long lastUpdated;

    public KeyBundle(List<Key> keys, String source, long cacheTime, boolean verifySSL,
                     String fileFormat, String keyType, List<String> keyUsage) throws ImportException {
        this.keys = keys;
        this.cacheTime = cacheTime;
        this.verifySSL = verifySSL;
        this.fileFormat = fileFormat.toLowerCase();
        this.keyType = keyType;
        this.keyUsage = keyUsage;
        this.remote = false;
        this.timeOut = 0;
        this.impJwks = new HashMap<String, List<Key>>();
        this.lastUpdated = 0;
        this.eTag = "";

        if (keys != null) {
            this.source = null;
            //doKeys(this.keys); why is this here?
        } else {
            if (source.startsWith("file://")) {
                this.source = source.substring(7);
            } else if (source.startsWith("http://") || source.startsWith("https://")) {
                this.source = source;
                this.remote = true;
            } else if (source.isEmpty()) {
                this.source = null;
            } else {
                if (new HashSet<String>(Arrays.asList("rsa", "der", "jwks")).contains(fileFormat.toLowerCase())) {
                    File file = new File(source);
                    if (file.exists() && file.isFile()) {
                        this.source = source;
                    } else {
                        throw new ImportException("No such file exists");
                    }
                } else {
                    throw new ImportException("Unknown source");
                }
            }

            if (!this.remote) {
                if (this.fileFormat.equals("jwks") || this.fileFormat.equals("jwk")) {
                    try {
                        this.doLocalJwk(this.source);
                    } catch (UpdateFailed updateFailed) {
                        logger.error("Local key updated from " + this.source + " failed.");
                    }
                } else if (this.fileFormat.equals("der")) {
                    doLocalDer(this.source, this.keyType, this.keyUsage);
                }
            }
        }
    }

    public KeyBundle() throws ImportException {
        this(null, "", 300, true, "jwk", "RSA", null);
    }

    public KeyBundle(List<Key> keyList, String keyType) throws ImportException {
        this(keyList, "", 300, true, "jwk", keyType, null);
    }

    public KeyBundle(List<Key> keyList, String keyType, List<String> usage) throws ImportException {
        this(keyList, "", 300, true, "jwk", keyType, usage);
    }

    public KeyBundle(String source, boolean verifySSL) throws ImportException {
        this(null, source, 300, verifySSL, "jwk", "RSA", null);
    }

    public KeyBundle(String source, String fileFormat, List<String> usage) throws ImportException {
        this(null, source, 300, true, fileFormat, "RSA", usage);
    }

    public void doKeys(List<Key> keys) {
        for (Key keyIndex : keys) {
            final String kty = keyIndex.getKty();
            List<String> usage = harmonizeUsage(keyIndex.getUse());
            keys.remove("use");
            boolean flag = false;
            for (String use : usage) {
                List<String> types = new ArrayList<String>() {{
                    add(kty);
                    add(kty.toLowerCase());
                    add(kty.toUpperCase());
                }};
                boolean isSuccess = true;
                Key key;
                for (String typeIndex : types) {
                    try {
                        switch(typeIndex) {
                            case "RSA":
                                key = new RSAKey("use");
                                break;
                            case "EC":
                                key = new ECKey("use");
                                break;
                            case "SYMKey":
                                key = new SYMKey("use");
                                break;
                            default:
                                throw new IllegalArgumentException("Encryption type: " + typeIndex + " isn't supported");
                        }
                    } catch (JWKException exception) {
                        logger.warn("While loading keys: " + exception);
                        isSuccess = false;
                    }

                    if (isSuccess) {
                        this.keys.add(key);
                        flag = true;
                        break;
                    }
                }
            }

            if (!flag) {
                logger.warn("While loading keys, UnknownKeyType: " + kty);
            }
        }
    }

    private static List<String> harmonizeUsage(List<String> uses) {
        Set<String> keys = map.keySet();
        Set<String> usagesSet = new HashSet<>();
        for (String use : uses) {
            if (keys.contains(use)) {
                usagesSet.add(use);
            }
        }
        return new ArrayList<>(usagesSet);
    }

    public void doLocalJwk(String fileName) throws UpdateFailed {
        JSONParser parser = new JSONParser();
        try {
            Object obj = parser.parse(new FileReader(
                    fileName));
            JSONObject jsonObject = (JSONObject) obj;
            JSONArray keys = (JSONArray) jsonObject.get("keys");
            Iterator<String> iterator = keys.iterator();
            List<Key> keysList = new ArrayList<Key>();
            while (iterator.hasNext()) {
                keysList.add(new Gson().fromJson(iterator.next(), Key.class));
            }
            doKeys(keysList);
        } catch (Exception e) {
            logger.error("Now 'keys' keyword in JWKS");
            throw new UpdateFailed("Local key updated from " + fileName + " failed.");
        } finally {
            this.lastUpdated = System.currentTimeMillis();
        }
    }

    public void doLocalDer(String fileName, String keyType, List<String> keyUsage) throws NotImplementedException {
        RSAKey rsaKey = rsaLoad(fileName);

        if (!keyType.equalsIgnoreCase("rsa")) {
            throw new NotImplementedException();
        }

        if (keyUsage.isEmpty()) {
            keyUsage = new ArrayList<String>() {{
                add("enc");
                add("sig");
            }};
        } else {
            keyUsage = harmonizeUsage(keyUsage);
        }

        for (String use : keyUsage) {
            RSAKey key = new RSAKey().loadKey(rsaKey);
            key.setUse(use);
            this.keys.add(key);
        }
        this.lastUpdated = System.currentTimeMillis();
    }

    public boolean doRemote() throws UpdateFailed, KeyException {
        Map<String, Object> args = new HashMap<>();
        args.put("verify", this.verifySSL);
        if (!this.eTag.isEmpty()) {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("If-None-Match", this.eTag);
            args.put("headers", jsonObject);
        }

        int statusCode;
        HttpResponse response;
        try {
            logger.debug("KeyBundle fetch keys from: " + this.source);
            HttpClient httpclient = new DefaultHttpClient();
            HttpGet httpget = new HttpGet(this.source);
            response = httpclient.execute(httpget);
            statusCode = response.getStatusLine().getStatusCode();
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new UpdateFailed("Couldn't make GET request to url: " + this.source);
        }

        if (statusCode == 304) {
            this.timeOut = System.currentTimeMillis() + this.cacheTime;
            this.lastUpdated = System.currentTimeMillis();

            List<Key> keys = this.impJwks.get("keys");
            if (keys != null) {
                doKeys(keys);
            } else {
                logger.error("No 'keys' keyword in JWKS");
                throw new UpdateFailed("No 'keys' keyword in JWKS");
            }
        } else if (statusCode == 200) {
            this.timeOut = System.currentTimeMillis() + this.cacheTime;
            try {
                this.impJwks = parseRemoteResponse(response);
            } catch (Exception exception) {
                exception.printStackTrace();
            }

            if (!this.impJwks.keySet().contains("keys")) {
                throw new UpdateFailed(this.source);
            }

            logger.debug("Loaded JWKS: " + response.toString() + " from " + this.source);
            List<Key> keys = this.impJwks.get("keys");
            if (keys != null) {
                doKeys(keys);
            } else {
                logger.error("No 'keys' keyword in JWKS");
                throw new UpdateFailed("No 'keys' keyword in JWKS");
            }

            Header[] headers = response.getHeaders("Etag");
            if (headers != null) {
                this.eTag = headers;
            } else {
                throw new KeyException("No 'Etag' keyword in headers");
            }
        } else {
            throw new UpdateFailed("Source: " + this.source + " status code: " + statusCode);
        }

        this.lastUpdated = System.currentTimeMillis();
        return true;
    }

    private JSONObject parseRemoteResponse(HttpResponse response) throws IOException, ParseException {
        if (!response.getHeaders("Content-Type").equals("application/json")) {
            logger.warn("Wrong Content_type");
        }

        logger.debug(String.format("Loaded JWKS: %s from %s", response.toString(), this.source));

        return (JSONObject) new JSONParser().parse(EntityUtils.toString(response.getEntity()));
    }

    private boolean upToDate() {

        boolean result = false;
        if (!this.keys.isEmpty()) {
            if (this.remote) {
                if (System.currentTimeMillis() > this.timeOut) {
                    if (update()) {
                        result = true;
                    }
                }
            }
        } else if (this.remote) {
            if (update()) {
                result = true;
            }
        }

        return result;
    }

    public boolean update() {
        boolean result = true;
        if (!this.source.isEmpty()) {
            List<Key> keys = this.keys;
            this.keys = new ArrayList<Key>();
            try {
                if (!this.remote) {
                    if (this.fileFormat.equals("jwks")) {
                        this.doLocalJwk(this.source);
                    } else if (this.fileFormat.equals("der")) {
                        doLocalDer(source, keyType, keyUsage);
                    }
                } else {
                    result = doRemote();
                }
            } catch (Exception exception) {
                logger.error("Key bundle updated failed: " + exception.toString());
                this.keys = keys;
                return false;
            }

            long now = System.currentTimeMillis();
            for (Key key : keys) {
                if (!keys.contains(key)) {
                    key.setInactiveSince();
                } else {
                    key.setInactiveSince(now);
                }
                this.keys.add(key);
            }
        }
        return result;
    }

    public List<Key> get(String typ) {

        this.upToDate();
        List<String> types = Arrays.asList(typ.toLowerCase(), typ.toUpperCase());

        if (!typ.isEmpty()) {
            List<Key> keys = new ArrayList<>();
            for (Key key : this.keys) {
                if (types.contains(key.getKty())) {
                    keys.add(key);
                }
            }
            return keys;
        } else {
            return this.keys;
        }
    }

    public List<Key> getKeys() {
        this.upToDate();
        return this.keys;
    }

    public List<Key> getActiveKeys() {
        List<Key> activeKeys = new ArrayList<>();
        for (Key key : this.keys) {
            if (key.getInactiveSince() == 0) {
                activeKeys.add(key);
            }
        }

        return activeKeys;
    }

    public void removeKeysByType(String typ) {
        List<String> types = Arrays.asList(typ.toLowerCase(), typ.toUpperCase());

        for (Key key : this.keys) {
            if (!types.contains(key.getKty())) {
                this.keys.remove(key);
            }
        }
    }

    public String toString() {
        return this.jwks();
    }

    public String jwks() {
        return jwks(false);
    }

    public String jwks(boolean isPrivate) {
        this.upToDate();
        List<Key> keys = new ArrayList<>();
        Key key;
        for (Key keyIndex : this.keys) {
            if (isPrivate) {
                key = keyIndex.serialize(isPrivate);
            } else {
                key = keyIndex.toDict();
                //TODO
            }
        }
    }

    public void append(Key key) {
        this.keys.add(key);
    }

    public void remove(Key key) {
        this.keys.remove(key);
    }

    public int getLength() {
        return this.keys.size();
    }

    public Key getKeyWithKid(String kid) {
        for (Key key : this.keys) {
            if (key.getKid().equals(kid)) {
                return key;
            }
        }

        update();

        for (Key key : this.keys) {
            if (key.getKid().equals(kid)) {
                return key;
            }
        }

        return null;
    }

    public List<String> getKids() {
        this.upToDate();
        List<String> kids = new ArrayList<>();
        for (Key key : this.keys) {
            if (!key.getKid().isEmpty()) {
                kids.add(key.getKid());
            }
        }

        return kids;
    }

    public void markAsInactive(String kid) {
        Key key = getKeyWithKid(kid);
        key.setInactiveSince(System.currentTimeMillis());
    }

    public void removeOutdated(float after, int when) throws TypeError {
        long now;
        if (when != 0) {
            now = when;
        } else {
            now = System.currentTimeMillis();
        }

        List<Key> keys = new ArrayList<>();
        for (Key key : this.keys) {
            if (!(key.getInactiveSince() && (key.getInactiveSince() + after < now))) {
                keys.add(key);
            }
        }

        this.keys = keys;
    }


    //----Not part of KeyBundle class, but I thought I should include these methods
    public KeyBundle keyBundleFromLocalFile(String filename, String type, List<String> usage) throws ImportException, UnknownKeyType {
        usage = harmonizeUsage(usage);
        KeyBundle keyBundle;
        type = type.toLowerCase();
        if (type.equals("jwks")) {
            keyBundle = new KeyBundle(filename, "jwks", usage);
        } else if (type.equals("der")) {
            keyBundle = new KeyBundle(filename, "der", usage);
        } else {
            throw new UnknownKeyType("Unsupported key type");
        }

        return keyBundle;
    }

    public void dumpJwks(List<KeyBundle> kbl, String target, boolean isPrivate) {
        throw new UnsupportedOperationException();
    }


}
*/
