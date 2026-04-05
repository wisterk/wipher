package me.wisterk.cipher.model;

import me.wisterk.cipher.Wipher;
import me.wisterk.cipher.session.GroupSession;
import me.wisterk.cipher.session.WipherSession;

import java.util.Arrays;
import java.util.Base64;

/**
 * Зашифрованное сообщение — минимальный payload, содержащий всё необходимое для расшифровки.
 * <p>
 * Структура:
 * <ul>
 *     <li>{@code nonce} — уникальный nonce/IV (12 байт для AES-GCM)</li>
 *     <li>{@code ciphertext} — зашифрованные данные + GCM authentication tag (16 байт)</li>
 * </ul>
 * </p>
 *
 * <h3>Формат сериализации</h3>
 * <p>
 * При преобразовании в байты или Base64 используется простой конкатенированный формат:
 * <pre>{@code
 * [ nonce (12 байт) | ciphertext (переменная длина) ]
 * }</pre>
 * Это самый эффективный и распространённый способ передачи зашифрованных сообщений.
 * </p>
 *
 * <h3>Основные методы</h3>
 * <ul>
 *     <li>{@link #toBytes()} — сериализация в байты</li>
 *     <li>{@link #fromBytes(byte[])} — десериализация из байт</li>
 *     <li>{@link #toBase64()} / {@link #fromBase64(String)} — удобная работа со строками</li>
 * </ul>
 *
 * <h3>Примеры использования</h3>
 * <pre>{@code
 * // 1. Создание зашифрованного payload (внутри WipherSession)
 * EncryptedPayload payload = new EncryptedPayload(nonce, ciphertext);
 *
 * // 2. Сериализация для передачи по сети
 * String base64 = payload.toBase64();
 * // отправка base64 по WebSocket / HTTP / etc.
 *
 * // 3. Десериализация на приёмной стороне
 * EncryptedPayload received = EncryptedPayload.fromBase64(receivedBase64);
 *
 * // 4. Расшифровка
 * String plaintext = session.decryptString(received);
 * }</pre>
 *
 * <h3>Гарантии и рекомендации</h3>
 * <ul>
 *     <li>Nonce всегда 12 байт (AES-GCM рекомендация)</li>
 *     <li>Каждое сообщение использует уникальный nonce — критично для безопасности</li>
 *     <li>fromBytes/fromBase64 проверяют минимальную длину (nonce + хотя бы 1 байт данных)</li>
 *     <li>Не модифицируйте массивы nonce/ciphertext после создания — они immutable по смыслу</li>
 *     <li>Для хранения/передачи рекомендуется Base64-вариант</li>
 *     <li>Record используется для краткости и иммутабельности</li>
 * </ul>
 *
 * @see WipherSession
 * @see Wipher
 * @see GroupSession
 */
public record EncryptedPayload(byte[] nonce, byte[] ciphertext) {

    /**
     * Длина nonce для AES-GCM.
     * <p>
     * 12 байт — рекомендуемый размер для AES-GCM (96 бит).
     * </p>
     */
    public static final int NONCE_LENGTH = 12;

    /**
     * Сериализует payload в единый байтовый массив: [nonce | ciphertext].
     * <p>
     * Формат используется для передачи по сети и хранения.
     * </p>
     *
     * @return байтовый массив [nonce (12 байт) + ciphertext]
     */
    public byte[] toBytes() {
        var result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
        return result;
    }

    /**
     * Десериализует payload из байтового массива [nonce | ciphertext].
     * <p>
     * Проверяет минимальную длину. Бросает исключение при некорректных данных.
     * </p>
     *
     * @param raw байты в формате [nonce (12 байт) | ciphertext]
     * @return восстановленный {@link EncryptedPayload}
     * @throws IllegalArgumentException если данных недостаточно
     */
    public static EncryptedPayload fromBytes(byte[] raw) {
        if (raw.length < NONCE_LENGTH + 1) {
            throw new IllegalArgumentException("Payload too short: expected at least " + (NONCE_LENGTH + 1) + " bytes");
        }
        var nonce = Arrays.copyOfRange(raw, 0, NONCE_LENGTH);
        var ciphertext = Arrays.copyOfRange(raw, NONCE_LENGTH, raw.length);
        return new EncryptedPayload(nonce, ciphertext);
    }

    /**
     * Сериализует payload в Base64-строку.
     * <p>
     * Удобно для передачи по текстовым каналам (WebSocket, HTTP, JSON и т.д.).
     * </p>
     *
     * @return Base64-строка
     */
    public String toBase64() {
        return Base64.getEncoder().encodeToString(toBytes());
    }

    /**
     * Десериализует payload из Base64-строки.
     *
     * @param base64 Base64-строка
     * @return восстановленный {@link EncryptedPayload}
     * @throws IllegalArgumentException при некорректных данных
     */
    public static EncryptedPayload fromBase64(String base64) {
        return fromBytes(Base64.getDecoder().decode(base64));
    }
}