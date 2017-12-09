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

package com.auth0.jwt.interfaces;

import com.auth0.jwt.exceptions.JWTDecodeException;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The Claim class holds the value in a generic way so that it can be recovered in many representations.
 */
public interface Claim {

    /**
     * Whether this Claim has a null value or not.
     *
     * @return whether this Claim has a null value or not.
     */
    boolean isNull();

    /**
     * Get this Claim as a Boolean.
     * If the value isn't of type Boolean or it can't be converted to a Boolean, null will be returned.
     *
     * @return the value as a Boolean or null.
     */
    Boolean asBoolean();

    /**
     * Get this Claim as an Integer.
     * If the value isn't of type Integer or it can't be converted to an Integer, null will be returned.
     *
     * @return the value as an Integer or null.
     */
    Integer asInt();

    /**
     * Get this Claim as an Long.
     * If the value isn't of type Long or it can't be converted to an Long, null will be returned.
     *
     * @return the value as an Long or null.
     */
    Long asLong();

    /**
     * Get this Claim as a Double.
     * If the value isn't of type Double or it can't be converted to a Double, null will be returned.
     *
     * @return the value as a Double or null.
     */
    Double asDouble();

    /**
     * Get this Claim as a String.
     * If the value isn't of type String or it can't be converted to a String, null will be returned.
     *
     * @return the value as a String or null.
     */
    String asString();

    /**
     * Get this Claim as a Date.
     * If the value can't be converted to a Date, null will be returned.
     *
     * @return the value as a Date or null.
     */
    Date asDate();

    /**
     * Get this Claim as an Array of type T.
     * If the value isn't an Array, null will be returned.
     *
     * @return the value as an Array or null.
     * @throws JWTDecodeException if the values inside the Array can't be converted to a class T.
     */
    <T> T[] asArray(Class<T> tClazz) throws JWTDecodeException;

    /**
     * Get this Claim as a List of type T.
     * If the value isn't an Array, null will be returned.
     *
     * @return the value as a List or null.
     * @throws JWTDecodeException if the values inside the List can't be converted to a class T.
     */
    <T> List<T> asList(Class<T> tClazz) throws JWTDecodeException;

    /**
     * Get this Claim as a generic Map of values.
     *
     * @return the value as instance of Map.
     * @throws JWTDecodeException if the value can't be converted to a Map.
     */
    Map<String, Object> asMap() throws JWTDecodeException;

    /**
     * Get this Claim as a custom type T.
     *
     * @return the value as instance of T.
     * @throws JWTDecodeException if the value can't be converted to a class T.
     */
    <T> T as(Class<T> tClazz) throws JWTDecodeException;
}
