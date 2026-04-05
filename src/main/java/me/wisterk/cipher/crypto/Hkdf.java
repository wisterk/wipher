package me.wisterk.cipher.crypto;

import me.wisterk.cipher.exception.WipherException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * HKDF (HMAC-based Key Derivation Function) — RFC 5869.
 *
 * Derives a cryptographically strong key from a DH shared secret.
 * The raw DH output is not suitable as an AES key directly — HKDF
 * extracts entropy and expands it into a uniform key.
 */
public final class Hkdf {

    private static final String HMAC_ALGO = "HmacSHA256";

    private Hkdf() {}

    /**
     * Derive a key from input keying material.
     *
     * @param ikm    input keying material (e.g. DH shared secret)
     * @param salt   optional salt (can be null — uses zero-filled)
     * @param info   context/application-specific info string
     * @param length desired output key length in bytes
     * @return derived key
     */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        // Extract
        if (salt == null || salt.length == 0) {
            salt = new byte[32]; // zero-filled
        }
        var prk = hmac(salt, ikm);

        // Expand
        int hashLen = 32; // SHA-256
        int n = (int) Math.ceil((double) length / hashLen);
        var okm = new byte[n * hashLen];
        var t = new byte[0];

        for (int i = 1; i <= n; i++) {
            var input = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, input, 0, t.length);
            System.arraycopy(info, 0, input, t.length, info.length);
            input[input.length - 1] = (byte) i;
            t = hmac(prk, input);
            System.arraycopy(t, 0, okm, (i - 1) * hashLen, hashLen);
        }

        return Arrays.copyOf(okm, length);
    }

    /**
     * Convenience: derive a 32-byte AES-256 key from a DH shared secret.
     */
    public static byte[] deriveAesKey(byte[] sharedSecret, String context) {
        return derive(sharedSecret, null, context.getBytes(), 32);
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            var mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new WipherException("HMAC computation failed", e);
        }
    }
}
