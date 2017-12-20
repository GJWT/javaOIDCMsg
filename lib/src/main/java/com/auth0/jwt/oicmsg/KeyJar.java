/*
package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.TypeError;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.jwts.JWT;
import com.google.common.base.Strings;
import org.junit.Assert;
import org.slf4j.LoggerFactory;

import java.security.KeyException;
import java.util.*;
import java.util.logging.Logger;

public class KeyJar {

    private boolean verifySSL;
    private KeyBundle keyBundle;
    private float removeAfter;
    private Map<String,List<KeyBundle>> issuerKeys;
    final private static org.slf4j.Logger logger = LoggerFactory.getLogger(KeyJar.class);

    public KeyJar(boolean verifySSL, KeyBundle keyBundle, int removeAfter) {
        this.verifySSL = verifySSL;
        this.keyBundle = keyBundle;
        this.removeAfter = removeAfter;
    }

    public KeyJar() throws ImportException {
        this.verifySSL = true;
        this.keyBundle = new KeyBundle();
        this.removeAfter = 3600;
    }

    public KeyBundle addUrl(String owner, String url, Map<String,String> args) throws KeyException, ImportException {
        if(url == null || url.isEmpty()) {
            throw new KeyException("No jwksUri");
        }

        KeyBundle keyBundle;
        if(url.contains("/localhost:") || url.contains("/localhost/")) {
            keyBundle = new KeyBundle(url, false);
        } else {
            keyBundle = new KeyBundle(url, verifySSL);
        }

        addKeyBundle(owner, keyBundle);

        return keyBundle;
    }

    public void addSymmetricKey(String owner, Key key, List<String> usage) throws ImportException {
        if(!issuerKeys.containsKey(owner)) {
            issuerKeys.put(owner, new ArrayList<KeyBundle>());
        }

        Key key = b64e(key.toString().getBytes());
        if(usage == null || usage.isEmpty()) {
            List<KeyBundle> kbList = new ArrayList<>();
            List<Key> keyList = new ArrayList<>(Arrays.asList(key));
            KeyBundle kb = new KeyBundle(keyList, "oct");
            kbList.add(kb);
            issuerKeys.put(owner, kbList);
        } else {
            List<KeyBundle> kbList;
            List<Key> keyList;
            KeyBundle kb;
            List<String> usageList = new ArrayList<>();
            for(String use : usage) {
                kbList = issuerKeys.get(owner);
                keyList = new ArrayList<>(Arrays.asList(key));
                usageList.add(use);
                kb = new KeyBundle(keyList, "oct", usageList);
                kbList.add(kb);
                issuerKeys.put(owner, kbList);
            }
        }
    }

    public void addKeyBundle(String owner, KeyBundle keyBundle) {
        List<KeyBundle> kbList;
        if(issuerKeys.get(owner) == null) {
            kbList = new ArrayList<>(Arrays.asList(keyBundle));
            issuerKeys.put(owner, kbList);
        } else {
            kbList = issuerKeys.get(owner);
            kbList.add(keyBundle);
            issuerKeys.put(owner, kbList);
        }
    }

    public Collection<List<KeyBundle>> getItems() {
        return this.issuerKeys.values();
    }

    public List<Key> getKeys(String keyUse, String keyType, String owner, String kid, Map<String,String> args) {
        String use;
        if(keyUse.equals("dec") || keyUse.equals("enc")) {
            use = "enc";
        } else {
            use = "sig";
        }

        List<KeyBundle> keyBundleList = null;
        if(owner != null && !owner.isEmpty()) {
            keyBundleList = this.issuerKeys.get(owner);

            if(keyBundleList == null) {
                if(owner.endsWith("/")) {
                    keyBundleList = this.issuerKeys.get(owner.substring(0, owner.length()-1));
                } else {
                    keyBundleList = this.issuerKeys.get(owner+"/");
                }
            }
        } else {
            keyBundleList = this.issuerKeys.get(owner);
        }

        if(keyBundleList == null) {
            return new ArrayList<>();
        }

        List<Key> keyListReturned = new ArrayList<>();
        List<Key> keyList = new ArrayList<>();
        for(KeyBundle keyBundle : keyBundleList) {
            if(keyType != null && !keyType.isEmpty()) {
                keyList = keyBundle.get(keyType);
            } else {
                keyList = keyBundle.getKeys();
            }

            for(Key key : keyList) {
                if(key.getInactiveSince() == 0 && !keyUse.equals("sig")) {
                    continue;
                }
                if(key.getUse() != null || use.equals(key.getUse())) {
                    if(kid != null) {
                        if(key.getKid().equals(kid)) {
                            keyListReturned.add(key);
                            break;
                        }
                    } else {
                        keyListReturned.add(key);
                    }
                }
            }
        }

        String name;
        if(keyType.equals("EC") && args.containsKey("alg")) {
            name = "P-{}" + args.get("alg").substring(2);
            List<Key> tempKeyList = new ArrayList<>();
            for(Key key : keyList) {
                try {
                    Assert.assertTrue(name.equals(((ECKey) key).getCrv()));
                } catch (AssertionError error) {
                    continue;
                } finally {
                    tempKeyList.add(key);
                }
            }
            keyList = tempKeyList;
        }

        if(use.equals("enc") && keyType.equals("oct") && owner != null && !owner.isEmpty()) {
            for(KeyBundle keyBundle : this.issuerKeys.get("")) {
                for(Key key : keyBundle.get(keyType)) {
                    if(key.getUse() == null || key.getUse() == use) {
                        keyList.add(key);
                    }
                }
            }
        }

        return keyList;
    }

    public List<Key> getSigningKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("sig", keyType, owner, kid, args);
    }

    public List<Key> getVerifyKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("ver", keyType, owner, kid, args);
    }

    public List<Key> getEncryptKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("enc", keyType, owner, kid, args);
    }

    public List<Key> getDecryptKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("dec", keyType, owner, kid, args);
    }

    public List<Key> keysByAlgAndUsage(String issuer, String algorithm, String usage) {
        String keyType;
        if(usage.equals("sig") || usage.equals("ver")) {
            keyType = algorithmToKeytypeForJWS(algorithm);
        } else {
            keyType = algorithmToKeytypeForJWE(algorithm);
        }

        return getKeys(usage, keyType, issuer, null, null);
    }

    public List<Key> getIssuerKeys(String issuer) {
        List<Key> keyList = new ArrayList<>();
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            keyList.addAll(keyBundle.getKeys());
        }
        return keyList;
    }

    private String algorithmToKeytypeForJWS(String algorithm) {
        if(algorithm == null || algorithm.toLowerCase().equals("none")) {
            return "none";
        } else if(algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            return "RSA";
        } else if(algorithm.startsWith("HS") || algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ES") || algorithm.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return null;
        }
    }

    private String algorithmToKeytypeForJWE(String algorithm) {
        if(algorithm.startsWith("RSA")) {
            return "RSA";
        } else if(algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ECDH")) {
            return "EC";
        } else {
            return null;
        }
    }

    public String matchOwner(String url) throws KeyException {
        for(String key : this.issuerKeys.keySet()) {
            if(url.startsWith(key)) {
                return key;
            }
        }

        throw new KeyException(String.format("No keys for %s", url));
    }

    public void loadKeys(Map<String,String> pcr, String issuer, boolean shouldReplace) {
        logger.debug("loading keys for issuer: " + issuer);

        if(shouldReplace || !this.issuerKeys.keySet().contains(issuer)) {
            this.issuerKeys.put(issuer, new ArrayList<KeyBundle>());
        }

        //this.addUrl(null, issuer, pcr.get("jwks_uri"));  ??
    }

    public KeyBundle find(String source, String issuer) {
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            if(keyBundle.getSource().equals(source)) {
                return keyBundle;
            }
        }

        return null;
    }

    public Map<String,List<Key>> exportsJwks(boolean isPrivate, String issuer) {
        List<Key> keys = new ArrayList<>();
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            for(Key key : keyBundle.getKeys()) {
                if(key.getInactiveSince() == 0) {
                    keys.addAll(key.serialize());
                }
            }
        }

        Map<String,List<Key>> keysMap = new HashMap<>();
        keysMap.put("keys", keys);
        return keysMap;
    }

    public Map<String,List<Key>> exportJwksAsJson(boolean isPrivate, String issuer) {
        return this.exportsJwks(isPrivate, issuer);
    }

    public void importJwks(Map<String,String> jwks, String issuer) throws ImportException {
        String keys = jwks.get("keys");
        List<KeyBundle> keyBundleList = this.issuerKeys.get("issuer");
        if(keyBundleList == null) {
            keyBundleList = new ArrayList<>();
        }

        keyBundleList.add(new KeyBundle(keys, this.verifySSL));
        this.issuerKeys.put(issuer, keyBundleList);
    }

    public void importJwksAsJson(String js, String issuer) {
        importJwks();
    }

    public void removeOutdated(int when) throws TypeError {
        List<KeyBundle> keyBundleList;
        for(String owner : this.issuerKeys.keySet()) {
            keyBundleList = new ArrayList<>();
            for(KeyBundle keyBundle : this.issuerKeys.get(owner)) {
                keyBundle.removeOutdated(this.removeAfter, when);
                if(keyBundle.getLength() > 0) {
                    keyBundleList.add(keyBundle);
                }
            }

            if(keyBundleList.size() > 0) {
                this.issuerKeys.put(owner, keyBundleList);
            } else {
                this.issuerKeys.remove(owner);
            }
        }
    }

    public List<Key> addKey(List<Key> keys, String owner, String use, String keyType, String kid,
                            Map<String,List<String>> noKidIssuer) {
        if(!this.issuerKeys.keySet().contains(owner)) {
            logger.error("Issuer " + owner + " not in keyjar");
            return keys;
        }

        logger.debug("Key set summary for " + owner + " : " + keySummary(this, owner));

        if(kid != null) {
            for(Key key : this.getKeys(use, owner, kid, keyType, null)) {
                if(key != null && !keys.contains(key)) {
                    keys.add(key);
                }
            }
            return keys;
        } else {
            List<Key> keyList = this.getKeys(use, "", owner, keyType, null);
            if(keyList.size() == 0) {
                return keys;
            } else if(keyList.size() == 1) {
                if(!keys.contains(keyList.get(0))) {
                    keys.add(keyList.get(0));
                }
            } else if(noKidIssuer != null) {
                List<String> allowedKids = noKidIssuer.get(owner);
                if(allowedKids != null) {
                    for(Key key : keyList) {
                        if(allowedKids.contains(key.getKid())) {
                            keys.add(key);
                        }
                    }
                } else {
                    keys.addAll(keyList);
                }
            }
        }
        return keys;
    }

    public void getJwtVerifyKeys(JWT jwt, Map<String,String> args) {
        List<Key> keyList = new ArrayList<>();
        JWTParser converter = new JWTParser();
        String keyType = algorithmToKeytypeForJWS(converter.parseHeader(jwttoString().getHeader().getAlgorithm().getName());
        String kid = jwt.getHeader().;
        String nki = args.get("no_kid_issuer");

    }

    public KeyJar copy() throws ImportException {
        KeyJar keyJar = new KeyJar();
        for(String owner : this.issuerKeys.keySet()) {
            //kj[owner] = [kb.copy() for kb in self[owner]]; how is kj[owner] being caled??
        }
        return keyJar;
    }
}
*/
