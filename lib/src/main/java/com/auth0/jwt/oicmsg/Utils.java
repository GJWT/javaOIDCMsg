package com.auth0.jwt.oicmsg;

import org.apache.commons.codec.binary.Base64;

public class Utils {

    public static String urlSafeEncode(String value) {
        value = Base64.encodeBase64URLSafeString(value.getBytes());
        StringBuilder sb = new StringBuilder(value);
        for (int i = sb.length() - 1;
             i >= 0;
             i--) {
            if (sb.charAt(i) == '=') {
                sb.deleteCharAt(i);
            } else {
                break;
            }
        }

        return sb.toString();
    }

    public static byte[] urlSafeDecode(String value) {
        byte[] stringToBytes = Base64.decodeBase64(value.getBytes());
        StringBuilder sb = new StringBuilder(new String(stringToBytes));
        for (int i = sb.length() - 1;
             i >= 0;
             i--) {
            if (sb.charAt(i) == '=') {
                sb.deleteCharAt(i);
            } else {
                break;
            }
        }

        return String.valueOf(sb).getBytes();
    }
}
