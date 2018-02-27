package oicclient.tuples;

public class Tuple {

    private Object a;
    private Object b;

    public Tuple(Object a, Object b) {
        this.a = a;
        this.b = b;
    }

    public Object getA() {
        return a;
    }

    public Object getB() {
        return b;
    }
}