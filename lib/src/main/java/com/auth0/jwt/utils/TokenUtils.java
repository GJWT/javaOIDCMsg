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

package com.auth0.jwt.utils;

import com.auth0.jwt.exceptions.JWTDecodeException;

public abstract class TokenUtils {

    /**
     * Splits the given token on the "." chars into a String array with 3 parts.
     *
     * @param token the string to split.
     * @return the array representing the 3 parts of the token.
     * @throws JWTDecodeException if the Token doesn't have 3 parts.
     */
    public static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }
}
