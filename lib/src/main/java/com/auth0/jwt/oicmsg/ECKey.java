/*
package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.spec.EllipticCurve;
import java.text.ParseException;
import java.util.*;

public class ECKey extends Key{

    private String crv;
    private Object x;
    private Object y;
    private Object d;
    private Object curve;
    final private static Logger logger = LoggerFactory.getLogger(ECKey.class);
    private static Set<String> longs = new HashSet<String>(Arrays.asList("x", "y", "d"));

    protected static Set<String> members = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "crv", "x", "y", "d"));
    public static Set<String> publicMembers = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "crv", "x", "y"));
    protected static Set<String> required = new HashSet<>(Arrays.asList("crv", "key", "x", "y"));

    public ECKey(String kty, String alg, String use, String kid, Key key, String crv, Object x, Object y, Object d,
                 Object curve, Map<String,String> args) {
        super(kty, alg, use, kid, "", "", "", key, args);
        this.crv = crv;
        this.x = x;
        this.y = y;
        this.d = d;
        this.curve = curve;

        if(this.crv != null && this.curve == null) {
            try {
                this.verify();
            } catch (HeaderError headerError) {
                headerError.printStackTrace();
            }
            this.deserialize();
        } else if(this.getKey() != null && (this.crv == null && this.curve == null)) {
            this.loadKey(key);
        }
    }

    public ECKey() {
        this("EC", "", "", "", null, "", null, null, null, null, null);
    }

    public void deserialize() {
        try {
            if(!(this.x instanceof Number)) {
                this.x = deser(this.x);
            }
            if(!(this.y instanceof Number)) {
                this.y = deser(this.y);
            }
        } catch (ParseException e) {
            logger.error("Couldn't parse value");
        }

        this.curve = byName(this.crv);
        if(this.d != null) {
            if(this.d instanceof String) {
                this.d = deser(this.d);
            }
        }
    }

    private EllipticCurve byName(String name) {
        if(name.equals("P-256")) {
            return EllipticCurve();
        } else if(name.equals("P-384")) {
            return EllipticCurve();
        } else if(name.equals("P-521")) {
            return EllipticCurve();
        }
    }

    public List<Object> getKey(boolean isPrivate) {
        if(isPrivate) {
            return new ArrayList<>(Arrays.asList(this.d));
        } else {
            return new ArrayList<>(Arrays.asList(this.x, this.y));
        }
    }

    public Object serialize(boolean isPrivate) throws SerializationNotPossible {
        if(this.crv == null && this.curve == null) {
            throw new SerializationNotPossible();
        }

        Map<String, String> args = common();
        args.put("crv", this.curve.getClass().getName());
        args.put("x", longToBase64(this.x));
        args.put("y", longToBase64(this.y));

        if(isPrivate && this.d != null) {
            args.put("d", longToBase64(this.d));
        }

        return args;
    }

    public ECKey loadKey(Key key) {
        this.curve = key;
        //how to return multiple objects in Java?
        return this;
    }

    public List<Object> getDecryptionKey() {
        return this.getKey(true);
    }

    public List<Object> getEncryptionKey(boolean isPrivate) {
        return this.getKey(isPrivate);
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public Object getX() {
        return x;
    }

    public void setX(Object x) {
        this.x = x;
    }

    public Object getY() {
        return y;
    }

    public void setY(Object y) {
        this.y = y;
    }

    public Object getD() {
        return d;
    }

    public void setD(Object d) {
        this.d = d;
    }

    public Object getCurve() {
        return curve;
    }

    public void setCurve(Object curve) {
        this.curve = curve;
    }

    public static Logger getLogger() {
        return logger;
    }

    public static Set<String> getLongs() {
        return longs;
    }

    public static void setLongs(Set<String> longs) {
        ECKey.longs = longs;
    }

    public static Set<String> getMembers() {
        return members;
    }

    public static void setMembers(Set<String> members) {
        ECKey.members = members;
    }

    public static Set<String> getPublicMembers() {
        return publicMembers;
    }

    public static void setPublicMembers(Set<String> publicMembers) {
        ECKey.publicMembers = publicMembers;
    }

    public static Set<String> getRequired() {
        return required;
    }

    public static void setRequired(Set<String> required) {
        ECKey.required = required;
    }
}
*/
