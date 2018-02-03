package com.auth0.jwt.oiccli.tuples;

public class Tuple5 {

    private Class classType;
    private boolean aBoolean;
    private Object object1;
    private Object object2;
    private boolean aBoolean2;

    public Tuple5(Class classType, boolean aBoolean, Object object1, Object object2, boolean aBoolean2) {
        this.classType = classType;
        this.aBoolean = aBoolean;
        this.object1 = object1;
        this.object2 = object2;
        this.aBoolean2 = aBoolean2;
    }

    public Class getClassType() {
        return classType;
    }

    public void setClassType(Class classType) {
        this.classType = classType;
    }

    public boolean isaBoolean() {
        return aBoolean;
    }

    public void setaBoolean(boolean aBoolean) {
        this.aBoolean = aBoolean;
    }

    public Object getObject1() {
        return object1;
    }

    public void setObject1(Object object1) {
        this.object1 = object1;
    }

    public Object getObject2() {
        return object2;
    }

    public void setObject2(Object object2) {
        this.object2 = object2;
    }

    public boolean isaBoolean2() {
        return aBoolean2;
    }

    public void setaBoolean2(boolean aBoolean2) {
        this.aBoolean2 = aBoolean2;
    }
}
