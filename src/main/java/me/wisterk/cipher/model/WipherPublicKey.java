package me.wisterk.cipher.model;

import me.wisterk.cipher.crypto.KeyGenerator;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * A public key that can be safely shared and transmitted.
 * Used for DH key agreement — the holder cannot decrypt, only contribute to shared secret.
 *
 * @param encoded the raw encoded key bytes
 */
public record WipherPublicKey(byte[] encoded) {

    /** Reconstruct from Base64 string (e.g. received from server). */
    public static WipherPublicKey fromBase64(String base64) {
        return new WipherPublicKey(Base64.getDecoder().decode(base64));
    }

    /** Convert to java.security.PublicKey for crypto operations. */
    public PublicKey toJavaPublicKey() {
        return KeyGenerator.decodePublicKey(encoded);
    }

    public String toBase64() {
        return Base64.getEncoder().encodeToString(encoded);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WipherPublicKey(byte[] encoded1))) return false;
        return Arrays.equals(encoded, encoded1);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public String toString() {
        var base64 = toBase64();
        return "WipherPublicKey[" + base64.substring(0, Math.min(16, base64.length())) + "...]";
    }
}
