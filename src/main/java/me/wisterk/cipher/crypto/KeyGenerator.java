package me.wisterk.cipher.crypto;

import me.wisterk.cipher.exception.WipherException;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.model.WipherPublicKey;
import me.wisterk.cipher.model.WipherPreKeyBundle;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * Генератор криптографических ключей для библиотеки Wipher (Wisterk Cipher).
 * <p>
 * Основные возможности:
 * <ul>
 *     <li>Генерация X25519 key pair (современный elliptic-curve Diffie-Hellman)</li>
 *     <li>Генерация случайного симметричного ключа (32 байта для AES-256-GCM)</li>
 *     <li>Создание pre-key bundle для оффлайн-установки сессий (X3DH)</li>
 *     <li>Декодирование публичного ключа из X.509 формата</li>
 * </ul>
 * </p>
 *
 * <h3>Почему X25519?</h3>
 * <ul>
 *     <li>Высокая скорость и безопасность (128-битный уровень безопасности)</li>
 *     <li>Компактные ключи (32 байта)</li>
 *     <li>Защита от side-channel атак</li>
 *     <li>Стандарт в современных мессенджерах (Signal, Matrix, Wire и т.д.)</li>
 * </ul>
 *
 * <h3>Примеры использования</h3>
 * <pre>{@code
 * // 1. Генерация пары ключей
 * WipherKeyPair keyPair = KeyGenerator.generateKeyPair();
 * WipherPublicKey publicKey = keyPair.toPublicKey();
 *
 * // 2. Генерация pre-key bundle (для оффлайн-сессий)
 * WipherPreKeyBundle bundle = KeyGenerator.generatePreKeyBundle(keyPair, 50);
 *
 * // 3. Генерация симметричного ключа (AES-256)
 * byte[] aesKey = KeyGenerator.generateSymmetricKey();
 *
 * // 4. Декодирование публичного ключа из байт
 * PublicKey decoded = KeyGenerator.decodePublicKey(encodedBytes);
 * }</pre>
 *
 * <h3>Гарантии и особенности</h3>
 * <ul>
 *     <li>Все методы потокобезопасны</li>
 *     <li>Используется {@link SecureRandom} для криптографически стойкой генерации</li>
 *     <li>При отсутствии X25519 в JVM бросается {@link WipherException}</li>
 *     <li>Pre-key bundle содержит identity key + N одноразовых pre-keys</li>
 *     <li>Декодирование использует стандартный X.509 формат</li>
 * </ul>
 *
 * @see WipherKeyPair
 * @see WipherPublicKey
 * @see WipherPreKeyBundle
 */
public final class KeyGenerator {

    private static final String ALGORITHM = "X25519";

    private KeyGenerator() {} // Utility class

    /**
     * Генерирует новую пару ключей X25519.
     * <p>
     * Возвращает объект {@link WipherKeyPair}, содержащий приватный и публичный ключ.
     * </p>
     *
     * @return пара ключей X25519
     * @throws WipherException если X25519 не поддерживается JVM
     */
    public static WipherKeyPair generateKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance(ALGORITHM);
            return new WipherKeyPair(kpg.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            throw new WipherException("X25519 not available in this JVM", e);
        }
    }

    /**
     * Генерирует случайный симметричный ключ длиной 32 байта (AES-256).
     * <p>
     * Используется для AES-GCM шифрования сообщений внутри сессии.
     * </p>
     *
     * @return 32 байта криптографически стойкого случайного ключа
     */
    public static byte[] generateSymmetricKey() {
        var key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Генерирует pre-key bundle для оффлайн-установки сессий (X3DH).
     * <p>
     * Содержит:
     * <ul>
     *     <li>identity public key</li>
     *     <li>N одноразовых pre-keys</li>
     * </ul>
     * </p>
     *
     * @param identityKeyPair identity-ключи текущего пользователя
     * @param preKeyCount количество pre-keys (рекомендуется 50–100)
     * @return pre-key bundle
     */
    public static WipherPreKeyBundle generatePreKeyBundle(WipherKeyPair identityKeyPair, int preKeyCount) {
        List<WipherPublicKey> preKeys = new ArrayList<>(preKeyCount);
        for (int i = 0; i < preKeyCount; i++) {
            preKeys.add(generateKeyPair().toPublicKey());
        }
        return new WipherPreKeyBundle(identityKeyPair.toPublicKey(), preKeys);
    }

    /**
     * Декодирует публичный ключ из X.509-encoded байт.
     * <p>
     * Используется при получении публичного ключа от другого пользователя.
     * </p>
     *
     * @param encoded X.509-encoded байты публичного ключа
     * @return {@link PublicKey} объект
     * @throws WipherException при ошибке декодирования
     */
    public static PublicKey decodePublicKey(byte[] encoded) {
        try {
            var keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new WipherException("Failed to decode public key", e);
        }
    }
}