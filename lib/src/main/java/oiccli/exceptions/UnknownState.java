package oiccli.exceptions;

public class UnknownState extends Throwable {
    public UnknownState(String state) {
        super(state);
    }
}
