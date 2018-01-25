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

import java.lang.reflect.Array;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

public class JsonMatcher extends TypeSafeDiagnosingMatcher<String> {

    private final String entry;
    private final String key;
    private final Matcher matcher;

    private JsonMatcher(String key, Object value, Matcher valueMatcher) {
        this.key = key;
        this.matcher = valueMatcher;
        if (value != null) {
            String stringValue = objectToString(value);
            entry = getStringKey(key) + stringValue;
        } else {
            entry = null;
        }
    }

    @Override
    protected boolean matchesSafely(String item, Description mismatchDescription) {
        if (item == null) {
            mismatchDescription.appendText("JSON was null");
            return false;
        }
        if (matcher != null) {
            if (!matcher.matches(item)) {
                matcher.describeMismatch(item, mismatchDescription);
                return false;
            }
            if (!item.contains(getStringKey(key))) {
                mismatchDescription.appendText("JSON didn't contained the key ").appendValue(key);
                return false;
            }
        }
        if (entry != null && !item.contains(entry)) {
            mismatchDescription.appendText("JSON was ").appendValue(item);
            return false;
        }

        return true;
    }

    @Override
    public void describeTo(Description description) {
        if (matcher == null) {
            description.appendText("A JSON with entry ")
                    .appendValue(entry);
        } else {
            matcher.describeTo(description);
        }
    }

    public static JsonMatcher hasEntry(String key, Object value) {
        return new JsonMatcher(key, value, null);
    }

    public static JsonMatcher hasEntry(String key, Matcher valueMatcher) {
        return new JsonMatcher(key, null, valueMatcher);
    }

    private String getStringKey(String key) {
        return "\"" + key + "\":";
    }

    private String objectToString(Object value) {
        String stringValue;
        if (value == null) {
            stringValue = "null";
        } else if (value instanceof String) {
            stringValue = "\"" + value + "\"";
        } else if (value instanceof Map) {
            stringValue = mapToString((Map<String, Object>) value);
        } else if (value instanceof Array) {
            stringValue = arrayToString((Object[]) value);
        } else if (value instanceof List) {
            stringValue = listToString((List<Object>) value);
        } else {
            stringValue = value.toString();
        }
        return stringValue;
    }

    private String arrayToString(Object[] array) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0;
             i < array.length;
             i++) {
            Object o = array[i];
            sb.append(objectToString(o));
            if (i + 1 < array.length) {
                sb.append(",");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String listToString(List<Object> list) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        Iterator<Object> it = list.iterator();
        while (it.hasNext()) {
            Object o = it.next();
            sb.append(objectToString(o));
            if (it.hasNext()) {
                sb.append(",");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private String mapToString(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        Iterator<Map.Entry<String, Object>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Object> e = it.next();
            sb.append("\"" + e.getKey() + "\":" + objectToString(e.getValue()));
            if (it.hasNext()) {
                sb.append(",");
            }
        }
        sb.append("}");
        return sb.toString();
    }
}