package com.auth0.jwt.oicmsg.oic;

import com.auth0.jwt.oicmsg.Message;
import com.auth0.jwt.oicmsg.Tuple5;
import com.auth0.jwt.oicmsg.exceptions.VerificationError;
import com.google.common.base.Strings;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

public class OpenIdSchema extends Message{

    private String birthDate;

    public OpenIdSchema() {
        Map<String,Tuple5> cParam = new HashMap<String,Tuple5>() {{
            put("subject", SINGLE_REQUIRED_STRING);
            put("name", SINGLE_OPTIONAL_STRING);
            put("givenName", SINGLE_OPTIONAL_STRING);
            put("familyName", SINGLE_OPTIONAL_STRING);
            put("middleName", SINGLE_OPTIONAL_STRING);
            put("nickname", SINGLE_OPTIONAL_STRING);
            put("preferredUsername", SINGLE_OPTIONAL_STRING);
            put("profile", SINGLE_OPTIONAL_STRING);
            put("picture", SINGLE_OPTIONAL_STRING);
            put("website", SINGLE_OPTIONAL_STRING);
            put("email", SINGLE_OPTIONAL_STRING);
            put("emailVerified", SINGLE_OPTIONAL_BOOLEAN);
            put("gender", SINGLE_OPTIONAL_STRING);
            put("birthdate", SINGLE_OPTIONAL_STRING);
            put("zoneInfo", SINGLE_OPTIONAL_STRING);
            put("locale", SINGLE_OPTIONAL_STRING);
            put("phoneNumber", SINGLE_OPTIONAL_STRING);
            put("phoneNumberVerified", SINGLE_OPTIONAL_BOOLEAN);
            put("address", OPTIONAL_ADDRESS);
            put("updatedAt", SINGLE_OPTIONAL_INT);
            put("claimNames", OPTIONAL_MESSAGE);
            put("claimSources", OPTIONAL_MESSAGE);
        }};
        setcParam(cParam);
    }

    public boolean verify(Map<String,Object> kwargs) throws Exception {
        new OpenIdSchema().verify(kwargs);
        String birthDate = this.getBirthDate();
        if(!Strings.isNullOrEmpty(birthDate)) {
            DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
            try {
                formatter.parse(birthDate);
            } catch (ParseException e) {
                formatter = new SimpleDateFormat("yyyy");
                try {
                    formatter.parse(birthDate);
                } catch (ParseException e1) {
                    formatter = new SimpleDateFormat("0000-MM-dd");
                    try {
                        formatter.parse(birthDate);
                    } catch (ParseException e2) {
                        throw new VerificationError("Birthdate format error" + this);
                    }
                }
            }
        }

        for(Object object : this.getValues()) {
            if(object == null) {
                return false;
            }
        }

        return true;
    }

    public String getBirthDate() {
        return birthDate;
    }
}
