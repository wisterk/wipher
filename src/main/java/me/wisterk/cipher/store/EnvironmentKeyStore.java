package me.wisterk.cipher.store;

import me.wisterk.cipher.exception.WipherException;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.session.WipherSession;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Хранилище ключей, которое загружает identity key pair из переменных окружения.
 * <p>
 * Сессии хранятся только в памяти (ephemeral) — идеально подходит для:
 * <ul>
 *     <li>Docker-контейнеров</li>
 *     <li>Serverless функций (AWS Lambda, Cloud Run и т.д.)</li>
 *     <li>Статeless сервисов, где identity ключи инжектятся через окружение</li>
 * </ul>
 * </p>
 *
 * <h3>Переменные окружения</h3>
 * <ul>
 *     <li>{@code WIPHER_PUBLIC_KEY} — Base64-encoded X.509 публичный ключ</li>
 *     <li>{@code WIPHER_PRIVATE_KEY} — Base64-encoded PKCS#8 приватный ключ</li>
 * </ul>
 *
 * <h3>Пример использования</h3>
 * <pre>{@code
 * // В Dockerfile или docker-compose.yml:
 * ENV WIPHER_PUBLIC_KEY=MCowBQYDK2VuBCIE...
 * ENV WIPHER_PRIVATE_KEY=MC4CAQAwBQYDK2VuBCIE...
 *
 * // В коде:
 * var store = new EnvironmentKeyStore();
 * var wipher = Wipher.create(store);
 * }</pre>
 *
 * <h3>Особенности поведения</h3>
 * <ul>
 *     <li>Если ключи не заданы в окружении — {@link #loadIdentityKeyPair()} вернёт пустой Optional</li>
 *     <li>При первом сохранении ключей выводит в stderr готовые строки для ENV (удобно для разработки)</li>
 *     <li>Сессии хранятся только в памяти и теряются при перезапуске процесса</li>
 *     <li>Thread-safe для сессий (ConcurrentHashMap)</li>
 *     <li>При ошибке декодирования/парсинга бросает {@link WipherException}</li>
 * </ul>
 *
 * <h3>Рекомендации</h3>
 * <ul>
 *     <li>В продакшене ключи должны быть зашифрованы (например, через Docker Secrets или HashiCorp Vault)</li>
 *     <li>Не используйте этот store для долгоживущих приложений, где нужна persistence сессий</li>
 *     <li>Для development удобно комбинировать с {@link EncryptedKeyStore}</li>
 * </ul>
 *
 * @see WipherKeyStore
 * @see EncryptedKeyStore
 * @see InMemoryKeyStore
 */
public final class EnvironmentKeyStore implements WipherKeyStore {

    public static final String ENV_PUBLIC_KEY = "WIPHER_PUBLIC_KEY";
    public static final String ENV_PRIVATE_KEY = "WIPHER_PRIVATE_KEY";

    private final Map<String, WipherSession> sessions = new ConcurrentHashMap<>();
    private volatile WipherKeyPair cached;

    /**
     * Сохраняет identity key pair и выводит в stderr готовые строки для переменных окружения.
     * <p>
     * Полезно при первом запуске — можно скопировать и добавить в конфигурацию контейнера.
     * </p>
     */
    @Override
    public void saveIdentityKeyPair(WipherKeyPair keyPair) {
        this.cached = keyPair;

        System.err.println("[Wipher] Identity key pair generated. Add these to your environment:");
        System.err.println("  export " + ENV_PUBLIC_KEY + "=" +
                Base64.getEncoder().encodeToString(keyPair.publicKey().getEncoded()));
        System.err.println("  export " + ENV_PRIVATE_KEY + "=" +
                Base64.getEncoder().encodeToString(keyPair.privateKey().getEncoded()));
    }

    /**
     * Загружает identity key pair из переменных окружения {@code WIPHER_PUBLIC_KEY} и {@code WIPHER_PRIVATE_KEY}.
     * <p>
     * Ключи должны быть в Base64 (X.509 для публичного, PKCS#8 для приватного).
     * </p>
     */
    @Override
    public Optional<WipherKeyPair> loadIdentityKeyPair() {
        if (cached != null) {
            return Optional.of(cached);
        }

        var pubB64 = System.getenv(ENV_PUBLIC_KEY);
        var privB64 = System.getenv(ENV_PRIVATE_KEY);

        if (pubB64 == null || privB64 == null) {
            return Optional.empty();
        }

        try {
            var kf = KeyFactory.getInstance("X25519");

            var pubSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubB64));
            var pub = kf.generatePublic(pubSpec);

            var privSpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privB64));
            var priv = kf.generatePrivate(privSpec);

            cached = new WipherKeyPair(pub, priv);
            return Optional.of(cached);
        } catch (Exception e) {
            throw new WipherException("Failed to load identity key pair from environment variables", e);
        }
    }

    @Override
    public void saveSession(String peerId, WipherSession session) {
        sessions.put(peerId, session);
    }

    @Override
    public Optional<WipherSession> loadSession(String peerId) {
        return Optional.ofNullable(sessions.get(peerId));
    }

    @Override
    public void removeSession(String peerId) {
        sessions.remove(peerId);
    }

    @Override
    public boolean hasSession(String peerId) {
        return sessions.containsKey(peerId);
    }
}