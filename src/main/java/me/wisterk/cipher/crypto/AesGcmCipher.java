package me.wisterk.cipher.crypto;

import me.wisterk.cipher.exception.WipherException;
import me.wisterk.cipher.model.EncryptedPayload;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM symmetric cipher.
 *
 * GCM (Galois/Counter Mode) provides both confidentiality and integrity —
 * if a single bit is tampered with, decryption fails (authentication tag mismatch).
 *
 * <pre>{@code
 * byte[] key = KeyGenerator.generateSymmetricKey(); // 32 bytes
 * var encrypted = AesGcmCipher.encrypt(key, "hello".getBytes());
 * byte[] decrypted = AesGcmCipher.decrypt(key, encrypted);
 * }</pre>
 */
public final class AesGcmCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int NONCE_BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcmCipher() {}

    /**
     * Encrypt data with AES-256-GCM.
     *
     * @param key       32-byte symmetric key
     * @param plaintext data to encrypt
     * @return encrypted payload (nonce + ciphertext with auth tag)
     */
    public static EncryptedPayload encrypt(byte[] key, byte[] plaintext) {
        try {
            var nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));

            var ciphertext = cipher.doFinal(plaintext);
            return new EncryptedPayload(nonce, ciphertext);
        } catch (Exception e) {
            throw new WipherException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypt AES-256-GCM encrypted data.
     *
     * @param key     32-byte symmetric key (same as used for encryption)
     * @param payload the encrypted payload
     * @return decrypted plaintext
     * @throws WipherException if key is wrong or data was tampered with
     */
    public static byte[] decrypt(byte[] key, EncryptedPayload payload) {
        try {
            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, payload.nonce()));

            return cipher.doFinal(payload.ciphertext());
        } catch (javax.crypto.AEADBadTagException e) {
            throw new WipherException("Decryption failed: wrong key or tampered data", e);
        } catch (Exception e) {
            throw new WipherException("AES-GCM decryption failed", e);
        }
    }
}
