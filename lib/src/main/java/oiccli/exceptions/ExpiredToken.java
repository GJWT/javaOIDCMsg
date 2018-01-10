package oiccli.exceptions;

public class ExpiredToken extends Exception{
    public ExpiredToken(String message) {
        super(message);
    }
}
