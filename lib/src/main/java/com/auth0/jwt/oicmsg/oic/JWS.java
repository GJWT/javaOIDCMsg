package com.auth0.jwt.oicmsg.oic;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.util.encoders.Base64;

public class JWS {

    private static final String HS_256 = "HS256";
    private static final String HS_384 = "HS384";
    private static final String HS_512 = "HS512";
    private static final String SHA_256 = "SHA-256";
    private static final String SHA_384 = "SHA-384";
    private static final String SHA_512 = "SHA-512";
    private static final String UTF_8 = "UTF-8";

    public static byte[] leftHash(String message, String hashFunction) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        if(hashFunction.equals(HS_256)) {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            String byteToString = new String(digest.digest(message.getBytes()));
            byteToString = byteToString.substring(0,16);
            return new String(Base64.encode(byteToString.getBytes())).getBytes(UTF_8);
        } else if(hashFunction.equals(HS_384)) {
            MessageDigest digest = MessageDigest.getInstance(SHA_384);
            String byteToString = new String(digest.digest(message.getBytes()));
            byteToString = byteToString.substring(0,24);
            return new String(Base64.encode(byteToString.getBytes())).getBytes(UTF_8);
        } else if(hashFunction.equals(HS_512)) {
            MessageDigest digest = MessageDigest.getInstance(SHA_512);
            String byteToString = new String(digest.digest(message.getBytes()));
            byteToString = byteToString.substring(0,32);
            return new String(Base64.encode(byteToString.getBytes())).getBytes(UTF_8);
        } else {
            throw new IllegalArgumentException("Not a proper hash function");
        }
    }
}
