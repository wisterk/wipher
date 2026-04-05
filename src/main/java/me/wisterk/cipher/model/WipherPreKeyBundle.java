package me.wisterk.cipher.model;

import java.util.List;

/**
 * A bundle of pre-generated public keys uploaded to a server.
 * Allows others to establish E2E sessions even when the owner is offline.
 *
 * @param identityKey the long-term identity public key
 * @param preKeys     one-time pre-keys (consumed on use)
 */
public record WipherPreKeyBundle(WipherPublicKey identityKey, List<WipherPublicKey> preKeys) {

    /** Get and conceptually "consume" the next available pre-key. */
    public WipherPublicKey takePreKey(int index) {
        if (index < 0 || index >= preKeys.size()) {
            throw new IndexOutOfBoundsException("No prekey at index " + index);
        }
        return preKeys.get(index);
    }

    public int preKeyCount() {
        return preKeys.size();
    }
}
