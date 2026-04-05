package me.wisterk.cipher.exception;

public class WipherException extends RuntimeException {

    public WipherException(String message) {
        super(message);
    }

    public WipherException(String message, Throwable cause) {
        super(message, cause);
    }
}
