package me.wisterk.cipher.session;

import me.wisterk.cipher.Wipher;
import me.wisterk.cipher.crypto.AesGcmCipher;
import me.wisterk.cipher.crypto.KeyGenerator;
import me.wisterk.cipher.model.EncryptedPayload;
import me.wisterk.cipher.stream.WipherDecryptingStream;
import me.wisterk.cipher.stream.WipherEncryptingStream;

import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Групповая E2E-сессия на основе модели **Sender Keys**.
 * <p>
 * Каждый участник генерирует свой sender-key и распространяет его остальным
 * участникам (зашифрованно через pairwise-сессии).
 * Сообщения шифруются один раз с помощью sender-key отправителя и рассылаются всем.
 * </p>
 *
 * <h3>Преимущества Sender Keys</h3>
 * <ul>
 *     <li>Одно шифрование на сообщение вместо N (где N — количество участников)</li>
 *     <li>Меньше трафика и вычислений</li>
 *     <li>При выходе участника — ротация sender-key отправителя</li>
 * </ul>
 *
 * <h3>Пример использования</h3>
 * <pre>{@code
 * // Создаём групповую сессию
 * var group = new GroupSession("team-chat");
 *
 * // Получаем свой sender-key (генерируется автоматически)
 * byte[] mySenderKey = group.getOrCreateMySenderKey();
 *
 * // Регистрируем sender-key другого участника (получен через pairwise-сессию)
 * group.addMemberKey("bob-id", bobSenderKey);
 *
 * // Шифруем сообщение для группы (используем свой sender-key)
 * var msg = group.encrypt("Привет команде!".getBytes());
 *
 * // Расшифровываем сообщение от Bob
 * byte[] plain = group.decrypt("bob-id", msg);
 * }</pre>
 *
 * <h3>Важные правила</h3>
 * <ul>
 *     <li>При добавлении/удалении участника необходимо вызвать {@link #rotateSenderKey()} и разослать новый ключ</li>
 *     <li>Каждый участник должен знать sender-key всех остальных</li>
 *     <li>Для отправки сообщения используется свой sender-key</li>
 *     <li>Для расшифровки — sender-key отправителя</li>
 * </ul>
 *
 * <h3>Поддержка потоков</h3>
 * <p>
 * Методы {@link #encryptStream} и {@link #decryptStream} позволяют работать с большими данными
 * (файлы, аудио, видео) без полной загрузки в память.
 * </p>
 *
 * @see WipherSession
 * @see Wipher
 * @see AesGcmCipher
 */
public final class GroupSession {

    private final String groupId;
    private byte[] mySenderKey;
    private final Map<String, byte[]> memberKeys = new ConcurrentHashMap<>();

    /**
     * Создаёт новую групповую сессию.
     *
     * @param groupId уникальный идентификатор группы
     */
    public GroupSession(String groupId) {
        this.groupId = groupId;
    }

    /**
     * Возвращает (или создаёт) sender-key текущего пользователя для этой группы.
     * <p>
     * Ключ генерируется один раз и кэшируется.
     * </p>
     *
     * @return 32-байтовый sender-key (копия)
     */
    public synchronized byte[] getOrCreateMySenderKey() {
        if (mySenderKey == null) {
            mySenderKey = KeyGenerator.generateSymmetricKey();
        }
        return mySenderKey.clone();
    }

    /**
     * Регистрирует sender-key участника группы.
     * <p>
     * Ключ должен быть получен через pairwise-сессию (зашифрованно).
     * </p>
     *
     * @param memberId  идентификатор участника
     * @param senderKey его sender-key
     */
    public void addMemberKey(String memberId, byte[] senderKey) {
        memberKeys.put(memberId, senderKey.clone());
    }

    /**
     * Удаляет участника из группы.
     * <p>
     * После удаления рекомендуется вызвать {@link #rotateSenderKey()}.
     * </p>
     *
     * @param memberId идентификатор участника
     */
    public void removeMember(String memberId) {
        memberKeys.remove(memberId);
    }

    /**
     * Ротирует sender-key текущего пользователя.
     * <p>
     * Должен вызываться при любом изменении состава группы (добавление/удаление).
     * Новый ключ нужно разослать всем оставшимся участникам через pairwise-сессии.
     * </p>
     *
     * @return новый sender-key (для распространения)
     */
    public synchronized byte[] rotateSenderKey() {
        mySenderKey = KeyGenerator.generateSymmetricKey();
        return mySenderKey.clone();
    }

    /**
     * Шифрует сообщение для группы (использует sender-key текущего пользователя).
     */
    public EncryptedPayload encrypt(byte[] plaintext) {
        return AesGcmCipher.encrypt(getOrCreateMySenderKey(), plaintext);
    }

    /**
     * Расшифровывает сообщение от конкретного отправителя.
     * <p>
     * Использует sender-key этого отправителя.
     * </p>
     *
     * @param senderId идентификатор отправителя
     * @param payload зашифрованный payload
     * @return расшифрованные байты
     * @throws IllegalStateException если sender-key отправителя неизвестен
     */
    public byte[] decrypt(String senderId, EncryptedPayload payload) {
        var key = memberKeys.get(senderId);
        if (key == null) {
            throw new IllegalStateException("No sender key for member: " + senderId);
        }
        return AesGcmCipher.decrypt(key, payload);
    }

    /**
     * Шифрует поток для группы (chunked AES-GCM).
     */
    public InputStream encryptStream(InputStream plaintext) {
        return WipherEncryptingStream.wrap(getOrCreateMySenderKey(), plaintext);
    }

    /**
     * Расшифровывает поток от конкретного отправителя.
     */
    public InputStream decryptStream(String senderId, InputStream encrypted) {
        var key = memberKeys.get(senderId);
        if (key == null) {
            throw new IllegalStateException("No sender key for member: " + senderId);
        }
        return WipherDecryptingStream.wrap(key, encrypted);
    }

    /**
     * Идентификатор группы.
     */
    public String groupId() {
        return groupId;
    }

    /**
     * Карта известных sender-keys участников (только для чтения).
     */
    public Map<String, byte[]> memberKeys() {
        return Collections.unmodifiableMap(memberKeys);
    }
}