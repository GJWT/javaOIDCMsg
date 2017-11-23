package com.auth0.jwt;

import com.auth0.jwt.creators.EncodeType;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The JWTDecoder class holds the decode method to parse a given JWT token into it's JWT representation.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTDecoder implements DecodedJWT {

    private final String[] parts;
    private final Header header;
    private final Payload payload;

    public JWTDecoder(String jwt, EncodeType encodeType) throws Exception {
        parts = TokenUtils.splitToken(jwt);
        final JWTParser converter = new JWTParser();
        String headerJson = null;
        String payloadJson = null;
        switch (encodeType) {
            case Base16:
                headerJson = StringUtils.newStringUtf8(Hex.decodeHex(parts[0]));
                payloadJson = StringUtils.newStringUtf8(Hex.decodeHex(parts[1]));
                break;
            case Base32: {
                Base32 base32 = new Base32();
                headerJson = StringUtils.newStringUtf8(base32.decode(parts[0]));
                payloadJson = StringUtils.newStringUtf8(base32.decode(parts[1]));
                break;
            }
            case Base64:
                headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
                payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
                break;
            case JsonEncode:
                break;
                    //token = jwtCreator.signJsonEncode();
        }
            //headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
            //headerJson = StringUtils.newStringUtf8(Hex.decodeHex(parts[0]));
            //payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
            //payloadJson = StringUtils.newStringUtf8(Hex.decodeHex(parts[1]));
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
}
