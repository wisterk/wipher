package me.wisterk.cipher.crypto;

import me.wisterk.cipher.exception.WipherException;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.model.WipherPublicKey;

import java.security.PublicKey;

/**
 * X25519 Diffie-Hellman key agreement.
 *
 * Both parties contribute their keys, and both compute the same shared secret
 * without ever transmitting it. An eavesdropper who sees both public keys
 * cannot derive the shared secret.
 *
 * <pre>{@code
 * // Alice and Bob each generate a key pair
 * var alice = KeyGenerator.generateKeyPair();
 * var bob   = KeyGenerator.generateKeyPair();
 *
 * // They exchange public keys (through any channel, even insecure)
 * byte[] secretAtAlice = KeyAgreement.agree(alice, bob.toPublicKey());
 * byte[] secretAtBob   = KeyAgreement.agree(bob, alice.toPublicKey());
 *
 * // secretAtAlice == secretAtBob — identical shared secret
 * }</pre>
 */
public final class KeyAgreement {

    private KeyAgreement() {}

    /**
     * Perform X25519 DH key agreement.
     *
     * @param myKeyPair   our key pair (private key used for computation)
     * @param theirPublic the other party's public key
     * @return 32-byte shared secret
     */
    public static byte[] agree(WipherKeyPair myKeyPair, WipherPublicKey theirPublic) {
        return agree(myKeyPair, theirPublic.toJavaPublicKey());
    }

    /**
     * Perform X25519 DH key agreement with a raw java.security.PublicKey.
     */
    public static byte[] agree(WipherKeyPair myKeyPair, PublicKey theirPublic) {
        try {
            var ka = javax.crypto.KeyAgreement.getInstance("X25519");
            ka.init(myKeyPair.privateKey());
            ka.doPhase(theirPublic, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new WipherException("Key agreement failed", e);
        }
    }
}
