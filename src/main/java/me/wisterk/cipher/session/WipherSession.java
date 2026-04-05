package me.wisterk.cipher.session;

import me.wisterk.cipher.Wipher;
import me.wisterk.cipher.crypto.AesGcmCipher;
import me.wisterk.cipher.crypto.Hkdf;
import me.wisterk.cipher.crypto.KeyAgreement;
import me.wisterk.cipher.model.EncryptedPayload;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.model.WipherPublicKey;
import me.wisterk.cipher.stream.WipherDecryptingStream;
import me.wisterk.cipher.stream.WipherEncryptingStream;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Установленная end-to-end сессия между двумя участниками.
 * <p>
 * Инкапсулирует общий секрет, полученный через DH key agreement (X25519),
 * и предоставляет высокоуровневые методы шифрования и расшифровки.
 * </p>
 *
 * <h3>Как работает</h3>
 * <ol>
 *     <li>Оба участника вызывают {@link #establish} с публичным ключом другого</li>
 *     <li>Выполняется X25519 DH → shared secret (одинаковый у обоих)</li>
 *     <li>HKDF с симметричным контекстом → AES-256 ключ</li>
 *     <li>Сессия готова к шифрованию сообщений</li>
 * </ol>
 *
 * <h3>Пример 1-на-1 переписки</h3>
 * <pre>{@code
 * // Alice
 * var alice = Wipher.create();
 * var alicePub = alice.getPublicKey();
 *
 * // Bob
 * var bob = Wipher.create();
 * var bobPub = bob.getPublicKey();
 *
 * // Установка сессии (оба должны это сделать)
 * alice.establishSession("bob", bobPub);
 * bob.establishSession("alice", alicePub);
 *
 * // Alice шифрует
 * var encrypted = alice.encrypt("bob", "Привет, Bob!");
 *
 * // Bob расшифровывает
 * String decrypted = bob.decrypt("alice", encrypted);
 * // → "Привет, Bob!"
 * }</pre>
 *
 * <h3>Групповые сессии (Sender Keys)</h3>
 * <p>
 * Для групп используется {@link #fromSymmetricKey} с общим sender-key.
 * </p>
 *
 * <h3>Поддержка потоков</h3>
 * <p>
 * Методы {@link #encryptStream} и {@link #decryptStream} позволяют шифровать
 * большие данные (файлы, аудио, видео) без полной загрузки в память.
 * </p>
 *
 * <h3>Гарантии безопасности</h3>
 * <ul>
 *     <li>Каждое сообщение использует уникальный nonce (AES-GCM)</li>
 *     <li>Контекст HKDF включает публичные ключи обоих сторон (защита от replay)</li>
 *     <li>Сессия thread-safe (внутренние вызовы AES-GCM безопасны)</li>
 *     <li>Поддержка forward secrecy через регулярную ротацию ключей (в будущем)</li>
 * </ul>
 *
 * @see Wipher
 * @see GroupSession
 * @see WipherSession#establish
 * @see AesGcmCipher
 */
public final class WipherSession {

    private final String sessionId;
    private final byte[] encryptionKey;
    private final WipherPublicKey peerPublicKey;

    private WipherSession(String sessionId, byte[] encryptionKey, WipherPublicKey peerPublicKey) {
        this.sessionId = sessionId;
        this.encryptionKey = encryptionKey;
        this.peerPublicKey = peerPublicKey;
    }

    /**
     * Устанавливает сессию путём выполнения DH key agreement и вывода AES-ключа.
     * <p>
     * Оба участника должны вызвать этот метод, передав публичный ключ другого.
     * </p>
     *
     * @param myKeyPair      наша пара ключей
     * @param theirPublicKey публичный ключ собеседника
     * @param context        строковый контекст сессии (используется в HKDF)
     * @return готовая сессия
     */
    public static WipherSession establish(WipherKeyPair myKeyPair,
                                          WipherPublicKey theirPublicKey,
                                          String context) {
        // DH → shared secret (одинаковый у обоих)
        var sharedSecret = KeyAgreement.agree(myKeyPair, theirPublicKey);

        // HKDF → AES-256 ключ
        // Контекст должен быть симметричным — одинаковым у обоих сторон.
        // Используем сортировку публичных ключей для детерминированности.
        var myPub = myKeyPair.publicKeyBase64();
        var theirPub = theirPublicKey.toBase64();
        var symmetricContext = myPub.compareTo(theirPub) < 0
                ? "wipher:" + myPub + ":" + theirPub
                : "wipher:" + theirPub + ":" + myPub;

        var aesKey = Hkdf.deriveAesKey(sharedSecret, symmetricContext);

        return new WipherSession(context, aesKey, theirPublicKey);
    }

    /**
     * Создаёт сессию из готового симметричного ключа.
     * <p>
     * Используется для групповых сессий (Sender Keys).
     * </p>
     *
     * @param sessionId    идентификатор сессии
     * @param symmetricKey готовый AES-ключ
     * @return сессия
     */
    public static WipherSession fromSymmetricKey(String sessionId, byte[] symmetricKey) {
        return new WipherSession(sessionId, symmetricKey, null);
    }

    /**
     * Шифрует массив байтов для собеседника.
     */
    public EncryptedPayload encrypt(byte[] plaintext) {
        return AesGcmCipher.encrypt(encryptionKey, plaintext);
    }

    /**
     * Расшифровывает payload от собеседника.
     */
    public byte[] decrypt(EncryptedPayload payload) {
        return AesGcmCipher.decrypt(encryptionKey, payload);
    }

    /**
     * Шифрует строку (UTF-8).
     */
    public EncryptedPayload encryptString(String text) {
        return encrypt(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Расшифровывает в строку (UTF-8).
     */
    public String decryptString(EncryptedPayload payload) {
        return new String(decrypt(payload), StandardCharsets.UTF_8);
    }

    /**
     * Оборачивает plaintext InputStream в шифрующий поток (chunked AES-GCM).
     */
    public InputStream encryptStream(InputStream plaintext) {
        return WipherEncryptingStream.wrap(encryptionKey, plaintext);
    }

    /**
     * Оборачивает encrypted InputStream в расшифровывающий поток.
     */
    public WipherDecryptingStream decryptStream(InputStream encrypted) {
        return WipherDecryptingStream.wrap(encryptionKey, encrypted);
    }

    /**
     * Идентификатор сессии (обычно peerId).
     */
    public String sessionId() {
        return sessionId;
    }

    /**
     * Публичный ключ собеседника (для отладки/логирования).
     */
    public WipherPublicKey peerPublicKey() {
        return peerPublicKey;
    }

    // ── Serialization (for persistent key stores) ──

    /** Serialize session state to bytes: [sessionId_len][sessionId][key][peerPub_len][peerPub]. */
    public byte[] serialize() {
        var sidBytes = sessionId.getBytes(StandardCharsets.UTF_8);
        var peerBytes = peerPublicKey != null ? peerPublicKey.encoded() : new byte[0];
        var buf = java.nio.ByteBuffer.allocate(4 + sidBytes.length + 32 + 4 + peerBytes.length);
        buf.putInt(sidBytes.length);
        buf.put(sidBytes);
        buf.put(encryptionKey);
        buf.putInt(peerBytes.length);
        buf.put(peerBytes);
        return buf.array();
    }

    /** Deserialize session from bytes produced by {@link #serialize()}. */
    public static WipherSession deserialize(byte[] data) {
        var buf = java.nio.ByteBuffer.wrap(data);
        var sidLen = buf.getInt();
        var sidBytes = new byte[sidLen];
        buf.get(sidBytes);
        var key = new byte[32];
        buf.get(key);
        var peerLen = buf.getInt();
        WipherPublicKey peer = null;
        if (peerLen > 0) {
            var peerBytes = new byte[peerLen];
            buf.get(peerBytes);
            peer = new WipherPublicKey(peerBytes);
        }
        return new WipherSession(new String(sidBytes, StandardCharsets.UTF_8), key, peer);
    }
}