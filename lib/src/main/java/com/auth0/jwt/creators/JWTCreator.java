// Copyright (c) 2017 The Authors of 'JWTS for Java'
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package com.auth0.jwt.creators;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.impl.Claims;
import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.impl.PayloadSerializer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * The JWTCreator class holds the sign method to generate a complete JWT (with Signature) from a given Header and Payload content.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTCreator {

    private final Algorithm algorithm;
    private final String headerJson;
    private final String payloadJson;

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this.algorithm = algorithm;
        try {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(ClaimsHolder.class, new PayloadSerializer());
            mapper.registerModule(module);
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
            headerJson = mapper.writeValueAsString(headerClaims);
            payloadJson = mapper.writeValueAsString(new ClaimsHolder(payloadClaims));
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }


    /**
     * Initialize a JWTCreator instance.
     *
     * @return a JWTCreator.Builder instance to configure.
     */
    public static JWTCreator.Builder init() {
        return new Builder();
    }

    /**
     * The Builder class holds the Claims that defines the JWT to be created.
     */
    public static class Builder {
        private final Map<String, Object> payloadClaims;
        private Map<String, Object> headerClaims;
        private boolean isNoneAlgorithmAllowed;
        public static EncodeType encodeTypeStatic = null;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
            this.isNoneAlgorithmAllowed = false;
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        public Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = new HashMap<>(headerClaims);
            return this;
        }

        /**
         * Add a specific Key Id ("kid") claim to the Header.
         * If the {@link Algorithm} used to sign this token was instantiated with a KeyProvider, the 'kid' value will be taken from that provider and this one will be ignored.
         *
         * @param keyId the Key Id value.
         * @return this same Builder instance.
         */
        public Builder withKeyId(String keyId) {
            this.headerClaims.put(Claims.KEY_ID, keyId);
            return this;
        }

        /**
         * Add a specific Issuer ("iss") claim to the Payload.
         *
         * @param issuer the Issuer value.
         * @return this same Builder instance.
         */
        public Builder withIssuer(String issuer) {
            addClaim(Claims.ISSUER, issuer);
            return this;
        }

        /**
         * Add a specific Subject ("sub") claim to the Payload.
         *
         * @param subject the Subject value.
         * @return this same Builder instance.
         */
        public Builder withSubject(String subject) {
            addClaim(Claims.SUBJECT, subject);
            return this;
        }

        /**
         * Add a specific Audience ("aud") claim to the Payload.
         * Allows for multiple audience
         *
         * @param audience the Audience value.
         * @return this same Builder instance.
         */
        public Builder withAudience(String... audience) {
            addClaim(Claims.AUDIENCE, audience);
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim to the Payload.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        public Builder withExpiresAt(Date expiresAt) {
            addClaim(Claims.EXPIRES_AT, expiresAt);
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim to the Payload.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        public Builder withNotBefore(Date notBefore) {
            addClaim(Claims.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim to the Payload.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        public Builder withIssuedAt(Date issuedAt) {
            addClaim(Claims.ISSUED_AT, issuedAt);
            return this;
        }

        /**
         * Add a specific JWT Id ("jti") claim to the Payload.
         *
         * @param jwtId the Token Id value.
         * @return this same Builder instance.
         */
        public Builder withJWTId(String jwtId) {
            addClaim(Claims.JWT_ID, jwtId);
            return this;
        }

        /**
         * Developer specifies whether they want to accept
         * NONE algorithms or not.
         *
         * @param isNoneAlgorithmAllowed
         * @return
         */
        public Builder setIsNoneAlgorithmAllowed(boolean isNoneAlgorithmAllowed) {
            this.isNoneAlgorithmAllowed = isNoneAlgorithmAllowed;
            return this;
        }

        public boolean getIsNoneAlgorithmAllowed() {
            return this.isNoneAlgorithmAllowed;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withNonStandardClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withNonStandardClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withNonStandardClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withNonStandardClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withNonStandardClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withNonStandardClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Creates a new JWT and signs it with the given algorithm
         * Defaults to Base64 encoding
         *
         * @param algorithm used to sign the JWT
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(Algorithm algorithm) throws Exception{
            return sign(algorithm, EncodeType.Base64);
        }

        /**
         * Creates a new JWT and signs it with the given algorithm
         *
         * @param algorithm used to sign the JWT
         * @param encodeType specifies which base encoding is required
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(Algorithm algorithm, EncodeType encodeType) throws Exception {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            if(encodeType == null) {
                throw new IllegalArgumentException("Encodetype cannot be null.");
            }
            headerClaims.put(Claims.ALGORITHM, algorithm.getName());
            headerClaims.put(Claims.TYPE, "JWT");
            String signingKeyId = algorithm.getSigningKeyId();
            if (signingKeyId != null) {
                withKeyId(signingKeyId);
            }
            JWTCreator jwtCreator = new JWTCreator(algorithm, headerClaims, payloadClaims);
            String token = null;
            switch (encodeType) {
                case Base16:
                    token = jwtCreator.signBase16Encoding();
                    encodeTypeStatic = EncodeType.Base16;
                    break;
                case Base32:
                    token = jwtCreator.signBase32Encoding();
                    encodeTypeStatic = EncodeType.Base32;
                    break;
                case Base64:
                    token = jwtCreator.defaultSign();
                    encodeTypeStatic = EncodeType.Base64;
                    break;
            }

            return token;
        }

        protected void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addClaim(String name, Object value) {
            if (value == null) {
                payloadClaims.remove(name);
                return;
            }
            payloadClaims.put(name, value);
        }
    }

    private String signBase16Encoding() throws UnsupportedEncodingException {
        String header = URLEncoder.encode(headerJson, StandardCharsets.UTF_8.name());
        String payload = URLEncoder.encode(payloadJson, StandardCharsets.UTF_8.name());

        byte[] bHeader = header.getBytes(StandardCharsets.UTF_8.name());
        String encodedHeader = Hex.encodeHexString(bHeader);

        byte[] bPayload = payload.getBytes(StandardCharsets.UTF_8.name());
        String encodedPayload = Hex.encodeHexString(bPayload);

        String content = String.format("%s.%s", encodedHeader, encodedPayload);
        byte[] signatureBytes = algorithm.sign(content.getBytes(StandardCharsets.UTF_8));
        String signature = Hex.encodeHexString(signatureBytes);
        String signatureFinal = URLEncoder.encode(signature, StandardCharsets.UTF_8.name());

        return String.format("%s.%s", content, signatureFinal);
    }

    private String signBase32Encoding() throws UnsupportedEncodingException{
        Base32 base32 = new Base32();
        String header = URLEncoder.encode(headerJson, StandardCharsets.UTF_8.name());
        String payload = URLEncoder.encode(payloadJson, StandardCharsets.UTF_8.name());

        byte[] bHeader = header.getBytes(StandardCharsets.UTF_8.name());
        String encodedHeader = base32.encodeAsString(bHeader);

        byte[] bPayload = payload.getBytes(StandardCharsets.UTF_8.name());
        String encodedPayload = base32.encodeAsString(bPayload);

        String content = String.format("%s.%s", encodedHeader, encodedPayload);
        byte[] signatureBytes = algorithm.sign(content.getBytes(StandardCharsets.UTF_8));
        String signature = base32.encodeAsString(signatureBytes);
        String signatureFinal = URLEncoder.encode(signature, StandardCharsets.UTF_8.name());

        return String.format("%s.%s", content, signatureFinal);
    }

    private String defaultSign() throws SignatureGenerationException {
        String header = Base64.encodeBase64URLSafeString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.encodeBase64URLSafeString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String content = String.format("%s.%s", header, payload);

        byte[] signatureBytes = algorithm.sign(content.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        return String.format("%s.%s", content, signature);
    }
}