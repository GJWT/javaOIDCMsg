/*
package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.google.common.primitives.Bytes;
import com.nimbusds.jose.util.Base64;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.util.*;

public class Key {

    final private static Logger logger = LoggerFactory.getLogger(Key.class);
    protected String kty;
    protected String alg;
    protected String use;
    protected String kid;
    protected String x5c;
    protected String x5t;
    protected String x5u;
    protected Key key;
    protected long inactiveSince;
    protected Map<String, String> args;
    private static Map<String, Object> longs = new HashMap<String, Object>();
    protected static Set<String> members = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "x5c", "x5t", "x5u"));
    public static Set<String> publicMembers = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "x5c", "x5t", "x5u"));
    protected static Set<String> required = new HashSet<>(Arrays.asList("kty"));

    public Key(String kty, String alg, String use, String kid, String x5c, String x5t, String x5u, Key key, Map<String, String> args) {
        this.kty = kty;
        this.alg = alg;
        this.use = use;
        this.kid = kid;
        this.x5c = x5c;
        this.x5t = x5t;
        this.x5u = x5u;
        this.inactiveSince = 0;
        this.key = key;
        this.args = args;
    }

    public Key() {
        this("", "", "", "", "", "", "", null, null);
    }

    public String getX5c() {
        return x5c;
    }

    public void setX5c(String x5c) {
        this.x5c = x5c;
    }

    public String getX5t() {
        return x5t;
    }

    public void setX5t(String x5t) {
        this.x5t = x5t;
    }

    public String getX5u() {
        return x5u;
    }

    public void setX5u(String x5u) {
        this.x5u = x5u;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public void setInactiveSince() {
        this.inactiveSince = System.currentTimeMillis();
    }

    public void setInactiveSince(long now) {
        this.inactiveSince = now;
    }

    public long getInactiveSince() {
        return inactiveSince;
    }

    public Map<String, String> toDict() {
        Map<String, String> hmap = serialize();
        for (String key : args.keySet()) {
            hmap.put(key, args.get(key));
        }
        return hmap;
    }

    public List<Key> serialize() {
        Map<String, String> hmap = common();
        this.key.
        //TODO
    }

    public Map<String, String> common() {
        Map<String, String> args = new HashMap<>();
        args.put("kty", this.kty);
        if (this.use != null && !this.use.isEmpty()) {
            args.put("use", this.use);
        }
        if (this.kid != null && !this.kid.isEmpty()) {
            args.put("kid", this.kid);
        }
        if (this.alg != null && !this.alg.isEmpty()) {
            args.put("alg", this.alg);
        }
        return args;
    }

    public String toString() {
        return this.toDict().toString();
    }

    public Key getKey() {
        return this.key;
    }

    public boolean verify() throws HeaderError {
        Object item = null;
        for (String key : longs.keySet()) {

            try {
                item = this.getClass().getField(key).get(this);
            } catch (Exception e1) {
                logger.error("Field " + key + " doesn't exist");
            }
            if (item == null || item instanceof Number) {
                continue;
            }

            if (item instanceof Bytes) {
                //item = item.decode('utf-8') ???
                //TODO
            }

            try {
                base64URLToLong(item);
            } catch (Exception e) {
                return false;
            } finally {
                for(String sign : new ArrayList<>(Arrays.asList("+", "/", "="))) {
                    if(((String) item).contains(sign)) {
                        return false;
                    }
                }
            }

            if (this.kid != null && !this.kid.isEmpty()) {
                try {
                    Assert.assertTrue(this.kid instanceof String);
                } catch (AssertionError error) {
                    throw new HeaderError("kid of wrong value type");
                }
            }
        }

        return true;
    }

    private void base64URLToLong(Object item) {

    }

    public boolean equals(Object other) {
        try {
            Assert.assertTrue(other instanceof Key);
            //Assert.assertTrue(); //TODO
            Key otherKey = (Key) other;
            Assert.assertEquals(this.getKty(), otherKey.kty);
            Assert.assertEquals(this.getAlg(), otherKey.alg);
            Assert.assertEquals(this.getUse(), otherKey.use);
            Assert.assertEquals(this.getKid(), otherKey.kid);
            Assert.assertEquals(this.getX5c(), otherKey.x5c);
            Assert.assertEquals(this.getX5t(), otherKey.x5t);
            Assert.assertEquals(this.getX5u(), otherKey.x5u);
        } catch (AssertionError error) {
            return false;
        } finally {
            return true;
        }
    }

    public List<String> getKeys() {
        return new ArrayList<>(this.toDict().keySet());
    }

    public byte[] thumbprint(String hashFunction, List<String> members); //TODO

    public byte[] thumbprint(String hashFunction) {
        thumbprint(hashFunction, null);
    }

    public void addKid() {
        this.kid = Base64.encode(this.thumbprint("SHA-256")).decodeToString();
    }


    protected static void deser(Object item) {
        return base64ToLong(item);
    }
}
*/
