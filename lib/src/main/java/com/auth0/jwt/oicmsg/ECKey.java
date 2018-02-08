package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import java.security.spec.EllipticCurve;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *     JSON Web key representation of a Elliptic curve key.
 According to RFC 7517 a JWK representation of a EC key can look like
 this::
 {"kty":"EC",
 "crv":"P-256",
 "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
 }

 Parameters according to https://tools.ietf.org/html/rfc7518#section-6.2
 */
public class ECKey extends Key {

    private String crv;
    private Object x;
    private Object y;
    private Object d;
    private Object curve;
    final private static Logger logger = LoggerFactory.getLogger(ECKey.class);
    //The elliptic curve specific attributes
    private static Set<String> longs = new HashSet<String>(Arrays.asList("x", "y", "d"));
    protected static Set<String> members = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "crv", "x", "y", "d"));
    public static Set<String> publicMembers = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "crv", "x", "y"));
    protected static Set<String> required = new HashSet<>(Arrays.asList("crv", "key", "x", "y"));

    public ECKey(String kty, String alg, String use, String kid, Key key, String crv, Object x, Object y, Object d,
                 Object curve, Map<String, String> args) {
        super(kty, alg, use, kid, "", "", "", key, args);
        this.crv = crv;
        this.x = x;
        this.y = y;
        this.d = d;
        this.curve = curve;

        if (this.crv != null && this.curve == null) {
            try {
                this.verify();
            } catch (HeaderError headerError) {
                headerError.printStackTrace();
            }
            this.deserialize();
        } else if (this.getKey() != null && (this.crv == null && this.curve == null)) {
            this.loadKey(key);
        }
    }

    public ECKey() {
        this("EC", "", "", "", null, "", null, null, null, null, null);
    }

    /**
     *   Starting with information gathered from the on-the-wire representation
         of an elliptic curve key (a JWK) initiate an
         cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
         or EllipticCurvePrivateKey instance. So we have to get from having::
         {
         "kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
         }
         to having a key that can be used for signing/verifying and/or
         encrypting/decrypting.
         If 'd' has value then we're dealing with a private key otherwise
         a public key. 'x' and 'y' must have values.
         If this.key has a value beforehand this will overwrite whatever
         was there to begin with.

         x, y and d (if present) must be strings or bytes.
     */
    public void deserialize() {
        try {
            if (!(this.x instanceof Number)) {
                this.x = deser(this.x);
            }
            if (!(this.y instanceof Number)) {
                this.y = deser(this.y);
            }
        } catch (ParseException e) {
            logger.error("Couldn't parse value");
        }

        this.curve = byName(this.crv);
        if (this.d != null) {
            if (this.d instanceof String) {
                this.d = deser(this.d);
            }
        }
    }

    private EllipticCurve byName(String name) {
        if (name.equals("P-256")) {
            return EllipticCurve();
        } else if (name.equals("P-384")) {
            return EllipticCurve();
        } else if (name.equals("P-521")) {
            return EllipticCurve();
        }
    }

    public List<Object> getKey(boolean isPrivate) {
        if (isPrivate) {
            return Arrays.asList(this.d);
        } else {
            return Arrays.asList(this.x, this.y);
        }
    }

    /**
     * Go from a
       cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
       or EllipticCurvePublicKey instance to a JWK representation.
     * @param isPrivate: Whether we should include the private parts or not.
     * @return A JWK as a hashmap
     * @throws SerializationNotPossible
     */
    public Object serialize(boolean isPrivate) throws SerializationNotPossible {
        if (this.crv == null && this.curve == null) {
            throw new SerializationNotPossible();
        }

        Map<String, String> args = common();
        args.put("crv", this.curve.getClass().getName());
        args.put("x", longToBase64(this.x));
        args.put("y", longToBase64(this.y));

        if (isPrivate && this.d != null) {
            args.put("d", longToBase64(this.d));
        }

        return args;
    }

    /**
     * Load an Elliptic curve key
     * @param key: An elliptic curve key instance
     * @return
     */
    public ECKey loadKey(Key key) {
        this.curve = key;
        //how to return multiple objects in Java?
        return this;
    }

    public List<Object> getDecryptionKey() {
        return this.getKey(true);
    }

    public List<Object> getEncryptionKey(boolean isPrivate) {
        //both for encryption and decryption.
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
