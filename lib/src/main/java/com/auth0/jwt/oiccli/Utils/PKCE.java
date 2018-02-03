package com.auth0.jwt.oiccli.Utils;

import com.auth0.jwt.oiccli.StringUtil;
import com.auth0.jwt.oiccli.exceptions.ExpiredToken;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class PKCE {
    private static final String S256 = "S256";
    private static final String S384 = "S384";
    private static final String S512 = "S512";
    private static final String SHA_256 = "SHA-256";
    private static final String SHA_384 = "SHA-384";
    private static final String SHA_512 = "SHA-512";

    public static Map<String, String> addCodeChallenge(ClientInfo clientInfo, String state) throws NoSuchAlgorithmException, NoSuchAlgorithmException {
        Integer cvLength = (Integer) clientInfo.getConfig().get("codeChallenge").get("length");
        if (cvLength == null) {
            cvLength = 64;
        }

        String codeVerifier = StringUtil.generateRandomString(cvLength);
        codeVerifier = Base64.encode(codeVerifier.getBytes());

        String method = (String) clientInfo.getConfig().get("codeChallenge").get("method");
        if (method == null) {
            method = S256;
        }

        MessageDigest digest= null;
        switch (method) {
            case S256:
                digest = MessageDigest.getInstance(SHA_256);
                break;
            case S384:
                digest = MessageDigest.getInstance(SHA_384);
                break;
            case S512:
                digest = MessageDigest.getInstance(SHA_512);
                break;
        }

        String codeVerifierHex = bytesToHex(codeVerifier.getBytes());

        byte[] codeVerifierHexByteArr = digest.digest(codeVerifierHex.getBytes());
        String codeChallenge = Base64.encode(codeVerifierHexByteArr);

        clientInfo.getStateDb().addInfo(state, codeVerifier, method);

        Map<String, String> hMap = new HashMap<>();
        hMap.put("codeChallenge", codeChallenge);
        hMap.put("codeChallengeMethod", method);

        return hMap;
    }

    private static String bytesToHex(byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static Object getCodeVerifier(ClientInfo clientInfo, String state) throws ExpiredToken {
        return clientInfo.getStateDb().getTokenInfo("state" + state).get("codeVerifier");
    }
}
