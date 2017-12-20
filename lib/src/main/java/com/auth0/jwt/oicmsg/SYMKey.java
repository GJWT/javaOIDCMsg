/*
package com.auth0.jwt.oicmsg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class SYMKey extends Key{

    final private static Logger logger = LoggerFactory.getLogger(SYMKey.class);
    protected static Set<String> members = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "k"));
    public static Set<String> publicMembers = new HashSet<>(Arrays.asList("kty", "alg", "use", "kid", "k"));
    protected static Set<String> required = new HashSet<>(Arrays.asList("k", "kty"));
    private String k;
    private static Map<String,Integer> alg2Keylen = new HashMap<String,Integer>(){{
        put("A128KW", 16);
        put("A192KW", 24);
        put("A256KW", 32);
        put("HS256", 32);
        put("HS384", 48);
        put("HS512", 64);
    }};

    public SYMKey(String kty, String alg, String use, String kid, Key key, String x5c,
                  String x5t, String x5u, String k, Map<String,String> args) {
        super(kty, alg, use, kid, x5c, x5t, x5u, key, args);
        this.k = k;

        if(this.key == null) {
            this.key = b64d(this.k.getBytes());
        }
    }

    public void deserialize() {
        this.key = b64d(this.k.getBytes());
    }

    public Map<String,String> serialize(boolean isPrivate) {
        Map<String,String> args = common();
        args.put("k", b64e(this.k.getBytes()).asUnicode());
        return args;
    }

    public String encryptionKey(String alg) throws JWKException {
        if(this.key == null) {
            deserialize();
        }

        int size = alg2Keylen.get(alg);

        String encryptedKey;
        if(size <= 32) {
            encryptedKey = sha256_digest(this.key).substring(0,size);
        } else if (size <= 48) {
            encryptedKey = sha384_digest(this.key).substring(0,size);
        } else if (size <= 64) {
            encryptedKey = sha512_digest(this.key).substring(0,size);
        } else {
            throw new JWKException("No support for symmetric keys > 512 bits");
        }

        logger.debug(String.format("Symmetric encryption key: %s", as_unicode(b64e(encryptedKey)));

        return encryptedKey;
    }
}
*/
