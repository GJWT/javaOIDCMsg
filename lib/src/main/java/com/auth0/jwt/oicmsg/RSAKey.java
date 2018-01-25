package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.google.common.base.Strings;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAKey extends Key {

    final private static Logger logger = LoggerFactory.getLogger(RSAKey.class);
    private static Set<String> longs = new HashSet<String>(Arrays.asList("n", "e", "d", "p", "q", "dp", "dq", "di", "qi"));
    private String n;
    private String e;
    private String d;
    private String p;
    private String q;
    private String dp;
    private String dq;
    private String di;
    private String qi;
    private RSAKey key;

    public RSAKey(String kty, String alg, String use, String kid, String x5c, String x5t, String x5u, Key key, String n,
                  String e, String d, String p, String q, String dp, String dq, String di, String qi, Map<String, String> args) {
        super(kty, alg, use, kid, x5c, x5t, x5u, key, args);
        members.addAll(Arrays.asList("n", "e", "d", "p", "q"));
        publicMembers.addAll(Arrays.asList("n", "e"));
        required = new HashSet<String>(Arrays.asList("kty", "n", "e"));
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.di = di;
        this.qi = qi;

        boolean hasPublicKeyParts = !this.n.isEmpty() && this.n.length() == this.e.length();
        boolean hasX509CertChain = this.getX5c().length() > 0;

        if (this.getKey() == null && (hasPublicKeyParts || hasX509CertChain)) {
            this.deserialize();
        } else if (this.getKey() != null && !(this.n != null && this.e != null)) {
            this.split();
        }
    }

    public RSAKey(String use) {
        this("RSA", "", use, "", "", "", "", null, "", "", "", "", "", "", "", "", "", null);
    }

    public void deserialize() throws DeserializationNotPossible {
        if (this.n != null && this.e != null) {
            Object item = null;
            for (String param : longs) {
                try {
                    item = this.getClass().getField(param).get(this);
                    if (item == null || (item instanceof Number)) {
                        continue;
                    } else {
                        item = deserialize(item);
                    }
                } catch (Exception e1) {
                    logger.error("Field " + param + " doesn't exist");
                } finally {
                    try {
                        this.getClass().getField(param).set(param, item);
                    } catch (Exception e1) {
                        logger.error("Field " + param + " doesn't exist");
                    }
                }
            }

            List<String> list = Arrays.asList(this.n, this.e);
            if (!Strings.isNullOrEmpty(this.d)) {
                list.add(this.d);
            }
            if (!Strings.isNullOrEmpty(this.p)) {
                list.add(this.p);
                if (!Strings.isNullOrEmpty(this.q)) {
                    list.add(this.q);
                }
                this.key = RSA.construct(tuple(list));  //TODO
            } else {
                this.key = RSA.construct(list) //TODO
            }
        } else if (this.x5c != null) {
            Base64.decode((int) this.x5c.getBytes()[0]);

            if (this.x5t != null) {
                if (Base64.decode() !=)

            }

            this.key =;
            this.split();
            if (this.x5c.length() > 1) {

            }
        } else {
            throw new DeserializationNotPossible();
        }
    }

    public Map<String, String> serialize(boolean isPrivate) throws SerializationNotPossible {
        if (this.key == null) {
            throw new SerializationNotPossible();
        }

        Map<String, String> args = common();

        publicMembers.addAll(longs);
        List<String> publicLongs = new ArrayList<>(publicMembers);
        for (String param : publicLongs) {
            try {
                Object item = this.getClass().getField(param).get(this);
                if (item != null) {
                    args.put(param, longToBase64(item));
                }
            } catch (Exception e1) {
                logger.error("Field " + param + " doesn't exist");
            }
        }

        if (isPrivate) {
            for (String param : longs) {
                if (!isPrivate && Arrays.asList("d", "p", "q", "dp", "dq", "di",
                        "qi").contains(param)) {
                    continue;
                }
                try {
                    Object item = this.getClass().getField(param).get(this);
                    if (item != null) {
                        args.put(param, longToBase64(item));
                    }
                } catch (Exception e1) {
                    logger.error("Field " + param + " doesn't exist");
                }

            }
        }

        return args;
    }

    private void split() {
        this.n = this.key.n;
        this.e = this.key.e;

        this.d = this.key.d;
        Object item = null;
        for (String param : Arrays.asList("p", "q")) {
            try {
                item = this.getClass().getField(param).get(this);
            } catch (Exception e1) {
                logger.error("Field " + param + " doesn't exist");
            } finally {
                if (item != null) {
                    //set attribute (which is in the form of a string) to a value
                }
            }
        }
    }

}

    public RSAKey loadKey(RSAKey key) {
        this.key = key;
        this.split();
        return key;
    }

    public Key encryptionKey() {
        if (this.key == null) {
            deserialize();
        }

        return this.key;
    }

    private String longToBase64(Object item) {
    }

    @Override
    public Map<String, String> serialize() {
        return serialize(false);
    }
}
