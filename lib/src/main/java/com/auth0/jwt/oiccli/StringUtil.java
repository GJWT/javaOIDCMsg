package com.auth0.jwt.oiccli;

import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;

public class StringUtil {

    public static String generateRandomString(int length) {
        return new RandomStringGenerator.Builder()
                .withinRange('0', 'z')
                .filteredBy(CharacterPredicates.LETTERS, CharacterPredicates.DIGITS)
                .build().generate(length);
    }

    public static String alg2keytype(String algorithm) {
        if (algorithm == null || algorithm.toLowerCase().equals("none")) {
            return "none";
        } else if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            return "RSA";
        } else if (algorithm.startsWith("HS") || algorithm.startsWith("A")) {
            return "oct";
        } else if (algorithm.startsWith("ES") || algorithm.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return null;
        }
    }
}