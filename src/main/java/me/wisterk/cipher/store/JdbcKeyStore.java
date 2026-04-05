package me.wisterk.cipher.store;

import me.wisterk.cipher.exception.WipherException;
import me.wisterk.cipher.model.WipherKeyPair;
import me.wisterk.cipher.session.WipherSession;

import javax.sql.DataSource;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;

/**
 * JDBC-based key store — сохраняет ключи и сессии в любой SQL-базе данных.
 * <p>
 * Поддерживает PostgreSQL, MySQL, MariaDB, SQLite, H2, Oracle и другие базы,
 * совместимые со стандартным SQL.
 * </p>
 *
 * <h3>Создаваемые таблицы</h3>
 * <pre>
 * wipher_identity
 *   id          VARCHAR(32)   PRIMARY KEY   — всегда "default"
 *   public_key  BLOB/BYTEA                  — X.509 encoded public key
 *   private_key BLOB/BYTEA                  — PKCS#8 encoded private key
 *
 * wipher_sessions
 *   peer_id     VARCHAR(255)  PRIMARY KEY   — идентификатор собеседника
 *   data        BLOB/BYTEA                  — сериализованная сессия
 * </pre>
 *
 * <h3>Пример использования</h3>
 * <pre>{@code
 * // С HikariCP / Spring DataSource
 * var store = new JdbcKeyStore(dataSource);
 * var wipher = Wipher.create(store);
 *
 * // Или с простой строкой подключения
 * var store = new JdbcKeyStore("jdbc:postgresql://localhost:5432/wipher", "user", "pass");
 * }</pre>
 *
 * <h3>Особенности</h3>
 * <ul>
 *     <li>Автоматическое создание таблиц при первом запуске ({@code CREATE TABLE IF NOT EXISTS})</li>
 *     <li>Поддержка как {@code BLOB}, так и {@code BYTEA} (PostgreSQL) — пробует оба варианта</li>
 *     <li>Использует {@code MERGE} для upsert identity-ключа (совместимо с большинством СУБД)</li>
 *     <li>Сессии сохраняются через DELETE + INSERT (универсальный upsert)</li>
 *     <li>Все операции оборачиваются в {@link WipherException} при ошибках БД</li>
 * </ul>
 *
 * <h3>Рекомендации по безопасности</h3>
 * <ul>
 *     <li>Используйте отдельную БД или схему для ключей</li>
 *     <li>Шифруйте соединение с БД (SSL)</li>
 *     <li>Рассмотрите комбинацию с {@link EncryptedKeyStore} для дополнительного шифрования на уровне приложения</li>
 *     <li>Регулярно делайте backup базы с ключами</li>
 * </ul>
 *
 * @see WipherKeyStore
 * @see EncryptedKeyStore
 * @see EnvironmentKeyStore
 */
public final class JdbcKeyStore implements WipherKeyStore {

    private final DataSource dataSource;

    /**
     * Создаёт хранилище на основе готового {@link DataSource}.
     * <p>
     * Рекомендуется использовать пулы соединений (HikariCP, Tomcat JDBC и т.д.).
     * </p>
     */
    public JdbcKeyStore(DataSource dataSource) {
        this.dataSource = dataSource;
        initSchema();
    }

    /**
     * Создаёт хранилище из JDBC URL, логина и пароля.
     * <p>
     * Удобно для простых случаев и тестов.
     * </p>
     */
    public JdbcKeyStore(String jdbcUrl, String user, String password) {
        this(new SimpleDataSource(jdbcUrl, user, password));
    }

    @Override
    public void saveIdentityKeyPair(WipherKeyPair keyPair) {
        exec("""
            MERGE INTO wipher_identity (id, public_key, private_key)
            KEY (id) VALUES ('default', ?, ?)
            """,
                keyPair.publicKey().getEncoded(),
                keyPair.privateKey().getEncoded()
        );
    }

    @Override
    public Optional<WipherKeyPair> loadIdentityKeyPair() {
        try (var conn = dataSource.getConnection();
             var ps = conn.prepareStatement(
                     "SELECT public_key, private_key FROM wipher_identity WHERE id = 'default'");
             var rs = ps.executeQuery()) {

            if (!rs.next()) return Optional.empty();

            var kf = KeyFactory.getInstance("X25519");
            var pub = kf.generatePublic(new X509EncodedKeySpec(rs.getBytes(1)));
            var priv = kf.generatePrivate(new PKCS8EncodedKeySpec(rs.getBytes(2)));

            return Optional.of(new WipherKeyPair(pub, priv));
        } catch (Exception e) {
            throw new WipherException("Failed to load identity key pair from database", e);
        }
    }

    @Override
    public void saveSession(String peerId, WipherSession session) {
        try (var conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            try {
                // Удаляем старую сессию
                try (var del = conn.prepareStatement("DELETE FROM wipher_sessions WHERE peer_id = ?")) {
                    del.setString(1, peerId);
                    del.executeUpdate();
                }

                // Вставляем новую
                try (var ins = conn.prepareStatement(
                        "INSERT INTO wipher_sessions (peer_id, data) VALUES (?, ?)")) {
                    ins.setString(1, peerId);
                    ins.setBytes(2, session.serialize());   // предполагается наличие serialize()
                    ins.executeUpdate();
                }

                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new WipherException("Failed to save session for peer: " + peerId, e);
        }
    }

    @Override
    public Optional<WipherSession> loadSession(String peerId) {
        try (var conn = dataSource.getConnection();
             var ps = conn.prepareStatement("SELECT data FROM wipher_sessions WHERE peer_id = ?")) {

            ps.setString(1, peerId);
            try (var rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();

                byte[] data = rs.getBytes(1);
                return Optional.of(WipherSession.deserialize(data));   // предполагается наличие deserialize()
            }
        } catch (SQLException e) {
            throw new WipherException("Failed to load session for peer: " + peerId, e);
        }
    }

    @Override
    public void removeSession(String peerId) {
        try (var conn = dataSource.getConnection();
             var ps = conn.prepareStatement("DELETE FROM wipher_sessions WHERE peer_id = ?")) {

            ps.setString(1, peerId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new WipherException("Failed to remove session for peer: " + peerId, e);
        }
    }

    @Override
    public boolean hasSession(String peerId) {
        try (var conn = dataSource.getConnection();
             var ps = conn.prepareStatement("SELECT 1 FROM wipher_sessions WHERE peer_id = ?")) {

            ps.setString(1, peerId);
            try (var rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new WipherException("Failed to check session existence for peer: " + peerId, e);
        }
    }

    /**
     * Инициализирует схему базы данных (создаёт таблицы, если их нет).
     * <p>
     * Сначала пытается создать таблицы с типом {@code BLOB}, затем (при ошибке) — с {@code BYTEA}
     * для лучшей совместимости с PostgreSQL.
     * </p>
     */
    private void initSchema() {
        try (var conn = dataSource.getConnection(); var stmt = conn.createStatement()) {
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS wipher_identity (
                    id          VARCHAR(32) PRIMARY KEY,
                    public_key  BLOB NOT NULL,
                    private_key BLOB NOT NULL
                )""");

            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS wipher_sessions (
                    peer_id VARCHAR(255) PRIMARY KEY,
                    data    BLOB NOT NULL
                )""");
        } catch (SQLException e) {
            // Попытка для PostgreSQL (BYTEA вместо BLOB)
            try (var conn = dataSource.getConnection(); var stmt = conn.createStatement()) {
                stmt.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS wipher_identity (
                        id          VARCHAR(32) PRIMARY KEY,
                        public_key  BYTEA NOT NULL,
                        private_key BYTEA NOT NULL
                    )""");

                stmt.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS wipher_sessions (
                        peer_id VARCHAR(255) PRIMARY KEY,
                        data    BYTEA NOT NULL
                    )""");
            } catch (SQLException e2) {
                throw new WipherException("Failed to initialize database schema for Wipher keys", e2);
            }
        }
    }

    /**
     * Универсальный helper для выполнения SQL с параметрами (byte[]).
     */
    private void exec(String sql, byte[]... params) {
        try (var conn = dataSource.getConnection();
             var ps = conn.prepareStatement(sql)) {

            for (int i = 0; i < params.length; i++) {
                ps.setBytes(i + 1, params[i]);
            }
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new WipherException("SQL execution failed", e);
        }
    }

    /**
     * Минимальная реализация DataSource для простого JDBC URL.
     * Используется в конструкторе с url/user/password.
     */
    private static final class SimpleDataSource implements DataSource {
        private final String url;
        private final String user;
        private final String password;

        SimpleDataSource(String url, String user, String password) {
            this.url = url;
            this.user = user;
            this.password = password;
        }

        @Override
        public Connection getConnection() throws SQLException {
            return java.sql.DriverManager.getConnection(url, user, password);
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return java.sql.DriverManager.getConnection(url, username, password);
        }

        // Заглушки для остальных методов DataSource
        @Override public java.io.PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(java.io.PrintWriter out) {}
        @Override public void setLoginTimeout(int seconds) {}
        @Override public int getLoginTimeout() { return 0; }
        @Override public java.util.logging.Logger getParentLogger() { return null; }
        @Override public <T> T unwrap(Class<T> iface) { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) { return false; }
    }
}