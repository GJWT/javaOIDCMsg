/*
package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import org.junit.Assert;

import java.security.KeyException;
import java.util.*;

public class KeyJar {

    private boolean verifySSL;
    private KeyBundle keyBundle;
    private int removeAfter;
    private Map<String,List<KeyBundle>> issuerKeys;

    public KeyJar(boolean verifySSL, KeyBundle keyBundle, int removeAfter) {
        this.verifySSL = verifySSL;
        this.keyBundle = keyBundle;
        this.removeAfter = removeAfter;
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
                Assert.assertTrue(name.equals(((ECKey) key).get);
            }
        }
    }
}
*/
