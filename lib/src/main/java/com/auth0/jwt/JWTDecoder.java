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

package com.auth0.jwt;

import com.auth0.jwt.creators.*;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.impl.Claims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import com.auth0.jwt.utils.TokenUtils;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;

import java.net.URLDecoder;
import java.util.*;

/**
 * The JWTDecoder class holds the decode method to parse a given JWT token into it's JWT representation.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTDecoder implements DecodedJWT {

    private final String[] parts;
    private final Header header;
    private final Payload payload;

    private static final String FACEBOOK = "facebook";
    private static final String GOOGLE = "google";

    public JWTDecoder(String jwt, EncodeType encodeType) throws Exception {
        parts = TokenUtils.splitToken(jwt);
        final JWTParser converter = new JWTParser();
        String headerJson = null;
        String payloadJson = null;
        switch (encodeType) {
            case Base16:
                headerJson = URLDecoder.decode(new String(Hex.decodeHex(parts[0])), "UTF-8");
                payloadJson = URLDecoder.decode(new String(Hex.decodeHex(parts[1])), "UTF-8");
                break;
            case Base32:
                Base32 base32 = new Base32();
                headerJson = URLDecoder.decode(new String(base32.decode(parts[0]), "UTF-8"));
                payloadJson = URLDecoder.decode(new String(base32.decode(parts[1]), "UTF-8"));
                break;
            case Base64:
                headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
                payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
                break;
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
    }

    @Override
    public String getAlgorithm() {
        return header.getAlgorithm();
    }

    @Override
    public String getType() {
        return header.getType();
    }

    @Override
    public String getContentType() {
        return header.getContentType();
    }

    @Override
    public String getKeyId() {
        return header.getKeyId();
    }

    @Override
    public Claim getHeaderClaim(String name) {
        return header.getHeaderClaim(name);
    }

    @Override
    public List<String> getIssuer() {
        return payload.getIssuer();
    }

    @Override
    public List<String> getSubject() {
        return payload.getSubject();
    }

    @Override
    public List<String> getAudience() {
        return payload.getAudience();
    }

    @Override
    public Date getExpiresAt() {
        return payload.getExpiresAt();
    }

    @Override
    public Date getNotBefore() {
        return payload.getNotBefore();
    }

    @Override
    public Date getIssuedAt() {
        return payload.getIssuedAt();
    }

    @Override
    public String getId() {
        return payload.getId();
    }

    @Override
    public Claim getClaim(String name) {
        return payload.getClaim(name);
    }

    @Override
    public Map<String, Claim> getClaims() {
        return payload.getClaims();
    }

    @Override
    public String getHeader() {
        return parts[0];
    }

    @Override
    public String getPayload() {
        return parts[1];
    }

    @Override
    public String getSignature() {
        return parts[2];
    }

    @Override
    public String getToken() {
        return String.format("%s.%s.%s", parts[0], parts[1], parts[2]);
    }

    public static GoogleOrFbJwtCreator decodeJWT(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        String issuer = claims.get(Claims.ISSUER).asString();
        GoogleOrFbJwtCreator googleOrFbJwtCreator = null;
        if(issuer.contains(FACEBOOK)) {
            googleOrFbJwtCreator = FbJwtCreator.build()
                    .withExp(claims.get(Claims.EXPIRES_AT).asDate())
                    .withIat(claims.get(Claims.ISSUED_AT).asDate())
                    .withAppId(claims.get(Claims.APP_ID).asString())
                    .withUserId(claims.get(Claims.USER_ID).asString());
        } else if(issuer.contains(GOOGLE)) {
            googleOrFbJwtCreator = GoogleJwtCreator.build()
                    .withPicture(claims.get(Claims.PICTURE).asString())
                    .withEmail(claims.get(Claims.EMAIL).asString())
                    .withIssuer(claims.get(Claims.ISSUER).asString())
                    .withSubject(claims.get(Claims.SUBJECT).asString())
                    .withAudience(claims.get(Claims.AUDIENCE).asString())
                    .withExp(claims.get(Claims.EXPIRES_AT).asDate())
                    .withIat(claims.get(Claims.ISSUED_AT).asDate())
                    .withName(claims.get(Claims.NAME).asString());
        } else {
            throw new IllegalArgumentException("Not from a Facebook or Google issuer");
        }

        return googleOrFbJwtCreator;
    }
}
