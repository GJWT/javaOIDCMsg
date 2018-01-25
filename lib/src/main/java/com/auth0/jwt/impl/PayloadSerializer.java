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

package com.auth0.jwt.impl;

import com.auth0.jwt.interfaces.constants.PublicClaims;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class PayloadSerializer extends StdSerializer<ClaimsHolder> {

    public PayloadSerializer() {
        this(null);
    }

    private PayloadSerializer(Class<ClaimsHolder> t) {
        super(t);
    }

    @Override
    public void serialize(ClaimsHolder holder, JsonGenerator gen, SerializerProvider provider) throws IOException {
        HashMap<Object, Object> safePayload = new HashMap<>();
        for (Map.Entry<String, Object> e : holder.getClaims().entrySet()) {
            switch (e.getKey()) {
                case PublicClaims.AUDIENCE:
                    if (e.getValue() instanceof String) {
                        safePayload.put(e.getKey(), e.getValue());
                        break;
                    }
                    String[] audArray = (String[]) e.getValue();
                    if (audArray.length == 1) {
                        safePayload.put(e.getKey(), audArray[0]);
                    } else if (audArray.length > 1) {
                        safePayload.put(e.getKey(), audArray);
                    }
                    break;
                case PublicClaims.EXPIRES_AT:
                case PublicClaims.ISSUED_AT:
                case PublicClaims.NOT_BEFORE:
                    safePayload.put(e.getKey(), dateToSeconds((Date) e.getValue()));
                    break;
                default:
                    if (e.getValue() instanceof Date) {
                        safePayload.put(e.getKey(), dateToSeconds((Date) e.getValue()));
                    } else {
                        safePayload.put(e.getKey(), e.getValue());
                    }
                    break;
            }
        }

        gen.writeObject(safePayload);
    }

    private long dateToSeconds(Date date) {
        return date.getTime() / 1000;
    }
}
