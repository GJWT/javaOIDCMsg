package com.auth0.jwt.oicmsg;

import java.util.Arrays;
import java.util.List;

public class Tuple5 {

    private List<Class<String>> vTypeList;
    private Class<String> vType;
    private boolean vRequired;
    private Object vSer;
    private Object vDSer;
    private boolean vNullAllowed;

    public Tuple5(List<Class<String>> vTypeList, boolean vRequired, Object vSer, Object vDSer, boolean vNullAllowed) {
        this.vTypeList = vTypeList;
        this.vRequired = vRequired;
        this.vSer = vSer;
        this.vDSer = vDSer;
        this.vNullAllowed = vNullAllowed;
    }

    public Tuple5(Class<String> vType, boolean vRequired, Object vSer, Object vDSer, boolean vNullAllowed) {
        this(Arrays.asList((Class<String>) null), vRequired, vSer, vDSer, vNullAllowed);
        this.vType = vType;
    }

    public List<Class<String>> getvTypeList() {
        return vTypeList;
    }

    public void setvTypeList(List<Class<String>> vTypeList) {
        this.vTypeList = vTypeList;
    }

    public Class<String> getvType() {
        return vType;
    }

    public void setvType(Class<String> vType) {
        this.vType = vType;
    }

    public boolean getVRequired() {
        return vRequired;
    }

    public void setVRequired(boolean vRequired) {
        this.vRequired = vRequired;
    }

    public Object getVSer() {
        return vSer;
    }

    public void setVSer(Object vSer) {
        this.vSer = vSer;
    }

    public Object getVDSer() {
        return vDSer;
    }

    public void setVDSer(Object vDSer) {
        this.vDSer = vDSer;
    }

    public boolean getVNullAllowed() {
        return vNullAllowed;
    }

    public void setVNullAllowed(boolean vNullAllowed) {
        this.vNullAllowed = vNullAllowed;
    }
}