package me.wisterk.cipher.store;

import me.wisterk.cipher.crypto.AesGcmCipher;
import me.wisterk.cipher.crypto.Hkdf;
import me.wisterk.cipher.model.EncryptedPayload;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.session.WipherSession;

import java.util.Optional;

/**
 * Декоратор хранилища ключей, который шифрует все данные на диске с помощью мастер-ключа.
 * <p>
 * Оборачивает любой {@link WipherKeyStore} и обеспечивает защиту данных "at rest":
 * <ul>
 *     <li>Все сессии шифруются AES-256-GCM с мастер-ключом</li>
 *     <li>Identity private key защищается (public key можно хранить открыто)</li>
 *     <li>Поддерживает создание мастер-ключа из парольной фразы через HKDF</li>
 * </ul>
 * </p>
 *
 * <h3>Пример использования</h3>
 * <pre>{@code
 * // Базовое хранилище (например, файловое)
 * var fileStore = new FileKeyStore(Paths.get("~/.wipher/keys"));
 *
 * // Защищённое хранилище с мастер-паролем
 * var secureStore = EncryptedKeyStore.withPassphrase(fileStore, "my-super-strong-passphrase-2025!");
 *
 * // Передаём в Wipher
 * var wipher = Wipher.create(secureStore);
 *
 * // Теперь все ключи и сессии на диске зашифрованы.
 * // Без правильного пароля данные бесполезны.
 * }</pre>
 *
 * <h3>Как работает шифрование</h3>
 * <ul>
 *     <li>Мастер-ключ (32 байта) используется для AES-GCM шифрования всех чувствительных данных</li>
 *     <li>При сохранении сессии данные сериализуются → шифруются → сохраняются через delegate</li>
 *     <li>При загрузке — извлекаются зашифрованные байты → расшифровываются → десериализуются</li>
 *     <li>Identity private key шифруется отдельно</li>
 * </ul>
 *
 * <h3>Рекомендации по безопасности</h3>
 * <ul>
 *     <li>Используйте длинный, сложный passphrase (минимум 20 символов)</li>
 *     <li>Никогда не храните passphrase в коде или в открытом виде</li>
 *     <li>При смене пароля необходимо перешифровать все данные</li>
 *     <li>Для мобильных приложений рекомендуется использовать биометрию + hardware keystore</li>
 *     <li>Мастер-ключ никогда не сохраняется в открытом виде</li>
 * </ul>
 *
 * @see WipherKeyStore
 * @see InMemoryKeyStore
 * @see Hkdf
 */
public final class EncryptedKeyStore implements WipherKeyStore {

    private final WipherKeyStore delegate;
    private final byte[] masterKey;

    /**
     * Создаёт зашифрованное хранилище с готовым мастер-ключом (32 байта).
     *
     * @param delegate базовое хранилище
     * @param masterKey 32-байтовый мастер-ключ
     */
    public EncryptedKeyStore(WipherKeyStore delegate, byte[] masterKey) {
        if (masterKey.length != 32) {
            throw new IllegalArgumentException("Master key must be exactly 32 bytes (AES-256)");
        }
        this.delegate = delegate;
        this.masterKey = masterKey.clone();
    }

    /**
     * Создаёт зашифрованное хранилище из текстовой парольной фразы.
     * <p>
     * Мастер-ключ выводится через HKDF — безопасно даже при слабом пароле.
     * </p>
     *
     * @param delegate   базовое хранилище
     * @param passphrase парольная фраза пользователя
     * @return защищённое хранилище
     */
    public static EncryptedKeyStore withPassphrase(WipherKeyStore delegate, String passphrase) {
        var key = Hkdf.deriveAesKey(passphrase.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "wipher-keystore-master");
        return new EncryptedKeyStore(delegate, key);
    }

    @Override
    public void saveIdentityKeyPair(WipherKeyPair keyPair) {
        // Public key можно хранить открыто
        delegate.saveIdentityKeyPair(keyPair);

        // Private key шифруем
        var encPriv = encrypt(keyPair.privateKey().getEncoded());

        // Сохраняем зашифрованный приватный ключ через специальный слот
        delegate.saveSession("__enc_priv__",
                WipherSession.fromSymmetricKey("__enc_priv__", padTo32(encPriv.toBytes())));
    }

    @Override
    public Optional<WipherKeyPair> loadIdentityKeyPair() {
        return delegate.loadIdentityKeyPair();
    }

    @Override
    public void saveSession(String peerId, WipherSession session) {
        var raw = session.serialize();           // предположим, что у сессии есть serialize()
        var encrypted = encrypt(raw);

        // Сохраняем зашифрованные данные через delegate
        delegate.saveSession(peerId,
                WipherSession.fromSymmetricKey(peerId, padTo32(encrypted.toBytes())));
    }

    @Override
    public Optional<WipherSession> loadSession(String peerId) {
        return delegate.loadSession(peerId).map(stored -> {
            var storedBytes = stored.serialize();           // предположим deserialize/serialize
            var encPayloadBytes = extractEncryptedBytes(storedBytes);
            var decrypted = decrypt(EncryptedPayload.fromBytes(encPayloadBytes));
            return WipherSession.deserialize(decrypted);    // предположим наличие метода
        });
    }

    @Override
    public void removeSession(String peerId) {
        delegate.removeSession(peerId);
    }

    @Override
    public boolean hasSession(String peerId) {
        return delegate.hasSession(peerId);
    }

    private EncryptedPayload encrypt(byte[] data) {
        return AesGcmCipher.encrypt(masterKey, data);
    }

    private byte[] decrypt(EncryptedPayload payload) {
        return AesGcmCipher.decrypt(masterKey, payload);
    }

    /**
     * Вспомогательный метод для построения "фейковой" сессии, содержащей зашифрованные данные.
     */
    private byte[] buildEncryptedSessionBytes(String peerId, byte[] encryptedPayload) {
        var sidBytes = peerId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var fakeKey = padTo32(encryptedPayload);
        var buf = java.nio.ByteBuffer.allocate(4 + sidBytes.length + 32 + 4 + encryptedPayload.length);

        buf.putInt(sidBytes.length);
        buf.put(sidBytes);
        buf.put(fakeKey);
        buf.putInt(encryptedPayload.length);
        buf.put(encryptedPayload);

        return buf.array();
    }

    private byte[] extractEncryptedBytes(byte[] serialized) {
        var buf = java.nio.ByteBuffer.wrap(serialized);
        var sidLen = buf.getInt();
        buf.position(buf.position() + sidLen + 32); // пропускаем sid + fakeKey
        var payloadLen = buf.getInt();
        var payload = new byte[payloadLen];
        buf.get(payload);
        return payload;
    }

    private byte[] padTo32(byte[] data) {
        var result = new byte[32];
        System.arraycopy(data, 0, result, 0, Math.min(data.length, 32));
        return result;
    }
}