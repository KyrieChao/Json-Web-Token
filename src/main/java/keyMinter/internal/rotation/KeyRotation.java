package keyMinter.internal.rotation;

import keyMinter.spi.LockProvider;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

@Slf4j
public class KeyRotation {
    private static final ConcurrentHashMap<String, ReentrantLock> LOCAL_LOCKS = new ConcurrentHashMap<>();
    private static final String LOCK_FILE_NAME = ".rotation.lock";
    
    // 可选的分布式锁提供者
    @Setter
    private static volatile LockProvider lockProvider;
    @FunctionalInterface
    public interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    @FunctionalInterface
    public interface FileSaverWithDir<T> {
        void accept(T t, Path tempDir) throws Exception;
    }

    @FunctionalInterface
    public interface MemoryUpdater<T> {
        void accept(T t) throws Exception;
    }

    /**
     * 原子性密钥轮换（支持本地锁和分布式锁）
     * 与旧方法签名 100% 兼容，直接替换即可
     */
    public static <T> boolean rotateKeyAtomic(String keyId, Path keyDir, ThrowingSupplier<T> keyGenerator,FileSaverWithDir<T> fileSaver, MemoryUpdater<T> memoryUpdater) throws IOException {
        // 1. 获取分布式锁（如果配置了）
        Lock distLock = null;
        if (lockProvider != null) {
            distLock = lockProvider.getLock(keyDir.toAbsolutePath().toString());
            try {
                if (!distLock.tryLock(30, TimeUnit.SECONDS)) {
                    log.warn("Failed to acquire distributed lock for {}", keyDir);
                    return false;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("Interrupted while acquiring distributed lock for {}", keyDir);
                return false;
            }
        }
        try {
            // 2. 获取本地 JVM 锁
            ReentrantLock localLock = LOCAL_LOCKS.computeIfAbsent(keyDir.toAbsolutePath().toString(), k -> new ReentrantLock());
            localLock.lock();
            try {
                // 确保父目录存在，否则无法创建锁文件
                if (!Files.exists(keyDir)) {
                    Files.createDirectories(keyDir);
                }
                // 3. 获取本地文件锁（跨进程）
                Path lockFile = keyDir.resolve(LOCK_FILE_NAME);
                try (RandomAccessFile raf = new RandomAccessFile(lockFile.toFile(), "rw");
                     FileLock ignored = raf.getChannel().lock()) {
                    return doRotateWithBackup(keyId, keyDir, keyGenerator, fileSaver, memoryUpdater);
                } catch (IOException e) {
                    log.error("Failed to acquire file lock for {}", keyDir, e);
                    return false;
                }
            } finally {
                localLock.unlock();
            }
        } finally {
            // 释放分布式锁
            if (distLock != null) {
                try {
                    distLock.unlock();
                } catch (Exception e) {
                    log.warn("Failed to release distributed lock", e);
                }
            }
        }
    }

    private static <T> boolean doRotateWithBackup(String keyId, Path keyDir, ThrowingSupplier<T> keyGenerator,
                                                  FileSaverWithDir<T> fileSaver, MemoryUpdater<T> memoryUpdater) {
        T newKey = null;
        Path tempDir = null;
        Path targetDir = keyDir.resolve(keyId);
        Path backupDir = keyDir.resolve(keyId + ".backup");
        try {
            log.debug("Generating new key for: {}", keyId);
            newKey = keyGenerator.get();

            log.debug("Creating temporary directory for key: {}", keyId);
            tempDir = createTempKeyDir(keyDir.getParent(), keyId);

            log.debug("Saving key files to temporary directory: {}", tempDir);
            fileSaver.accept(newKey, tempDir);

            writeVersionMetadata(tempDir, keyId);
            applyRestrictivePermissionsRecursively(tempDir);

            if (Files.exists(targetDir)) {
                createBackup(targetDir, backupDir);
            }

            log.debug("Atomically moving temporary directory to target: {}", targetDir);
            moveTempToTarget(tempDir, targetDir);

            log.debug("Updating memory mappings for key: {}", keyId);
            memoryUpdater.accept(newKey);

            log.info("Key rotation completed successfully for key: {}", keyId);
            cleanupBackup(backupDir);
            cleanupOldBackups(targetDir.getParent(), keyId);
            return true;
        } catch (Exception e) {
            log.error("Key rotation failed for key {}: {}", keyId, e.getMessage());
            cleanupOnFailure(tempDir, targetDir, newKey);
            restoreFromBackup(targetDir, backupDir);
            return false;
        }
    }
    private static void writeVersionMetadata(Path tempDir, String keyId) {
        try {
            Path meta = tempDir.resolve("version.json");
            String content = "{\"keyId\":\"" + keyId + "\",\"createdTime\":\"" + LocalDateTime.now() + "\"}";
            Files.writeString(meta, content);
        } catch (Exception e) {
             log.error("Failed to write version metadata for key {}: {}", keyId, e.getMessage());
             throw new RuntimeException("Failed to write version metadata", e);
        }
    }

    /**
     * 创建临时密钥目录
     */
    private static Path createTempKeyDir(Path parentDir, String keyId) throws IOException {
        // 确保父目录存在
        if (!Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

        // 生成唯一的临时目录名
        String tempDirName = ".tmp-" + keyId + "-" + UUID.randomUUID().toString().substring(0, 8) +
                "-" + System.currentTimeMillis();

        // 创建临时目录
        Path tempDir = parentDir.resolve(tempDirName);
        Files.createDirectories(tempDir);
        log.debug("Created temporary directory: {}", tempDir);

        return tempDir;
    }

    /**
     * 原子性移动临时目录到目标位置
     */
    private static void moveTempToTarget(Path tempDir, Path targetDir) throws IOException {
        if (tempDir == null || !Files.exists(tempDir)) {
            throw new IOException("Temporary directory does not exist: " + tempDir);
        }

        // 确保目标目录的父目录存在
        Path parentDir = targetDir.getParent();
        if (!Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

        // 如果目标目录已存在，先删除（标准轮换场景）
        if (Files.exists(targetDir)) {
            log.debug("Target directory already exists, deleting: {}", targetDir);
            deleteDirectoryRecursively(targetDir);
        }

        // 原子性移动
        Files.move(tempDir, targetDir, StandardCopyOption.ATOMIC_MOVE);
        log.debug("Moved {} to {} atomically", tempDir, targetDir);
    }

    private static void createBackup(Path targetDir, Path backupDir) throws IOException {
        if (Files.exists(backupDir)) {
            deleteDirectoryRecursively(backupDir);
        }
        Files.createDirectories(backupDir);
        try (var paths = Files.walk(targetDir)) {
            paths.forEach(p -> {
                Path rel = targetDir.relativize(p);
                Path dest = backupDir.resolve(rel);
                try {
                    if (Files.isDirectory(p)) {
                        Files.createDirectories(dest);
                    } else {
                        Files.copy(p, dest);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
        log.debug("Created backup at {}", backupDir);
    }

    private static void restoreFromBackup(Path targetDir, Path backupDir) {
        try {
            if (Files.exists(backupDir)) {
                deleteDirectoryRecursively(targetDir);
                Files.createDirectories(targetDir);
                try (var paths = Files.walk(backupDir)) {
                    paths.forEach(p -> {
                        Path rel = backupDir.relativize(p);
                        Path dest = targetDir.resolve(rel);
                        try {
                            if (Files.isDirectory(p)) {
                                Files.createDirectories(dest);
                            } else {
                                Files.copy(p, dest, StandardCopyOption.REPLACE_EXISTING);
                            }
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
                }
                log.warn("Restored target dir from backup: {}", backupDir);
            }
        } catch (Exception e) {
            log.error("Failed to restore from backup {}: {}", backupDir, e.getMessage());
        }
    }

    private static void cleanupBackup(Path backupDir) {
        try {
            if (Files.exists(backupDir)) {
                deleteDirectoryRecursively(backupDir);
            }
        } catch (IOException e) {
            log.debug("Failed to cleanup backup {}: {}", backupDir, e.getMessage());
        }
    }

    private static void applyRestrictivePermissionsRecursively(Path dir) {
        try (var paths = Files.walk(dir)) {
            paths.forEach(p -> {
                try {
                    applyRestrictivePermissions(p);
                } catch (Exception e) {
                     log.warn("Failed to apply restrictive permissions to {}: {}", p, e.getMessage());
                     // 这里可以选择是否抛出异常，视安全策略而定。
                     // 严格模式下应该抛出异常，防止密钥权限过宽。
                     throw new RuntimeException("Failed to apply restrictive permissions", e);
                }
            });
        } catch (IOException e) {
            log.warn("Failed to apply restrictive permissions: {}", e.getMessage());
            throw new RuntimeException("Failed to walk directory for permissions", e);
        }
    }

    private static void applyRestrictivePermissions(Path path) throws IOException {
        FileSystem fs = FileSystems.getDefault();
        boolean posix = fs.supportedFileAttributeViews().contains("posix");
        if (posix) {
            PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
            if (view != null) {
                var perms = java.util.EnumSet.noneOf(PosixFilePermission.class);
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                view.setPermissions(perms);
            }
        } else {
            AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (aclView != null) {
                UserPrincipal owner = Files.getOwner(path);
                AclEntry entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
                                AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.WRITE_ATTRIBUTES,
                                AclEntryPermission.READ_ACL, AclEntryPermission.WRITE_ACL, AclEntryPermission.WRITE_OWNER,
                                AclEntryPermission.EXECUTE, AclEntryPermission.DELETE, AclEntryPermission.DELETE_CHILD, AclEntryPermission.SYNCHRONIZE)
                        .build();
                aclView.setAcl(java.util.List.of(entry));
            }
        }
    }

    /**
     * 保留最新 3 份备份，其余删除
     */
    private static void cleanupOldBackups(Path keyDir, String keyId) {
        try (var s = Files.list(keyDir.getParent())) {
            s.filter(p -> p.getFileName().toString().matches(Pattern.quote(keyId) + "\\.backup\\.\\d+"))
                    .sorted(Comparator.reverseOrder())
                    .skip(3)
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException e) {
                            log.debug("Failed to delete old backup {}: {}", p, e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.debug("Failed to cleanup old backups for {}: {}", keyId, e.getMessage());
        }
    }

    /**
     * 清理失败时的残留资源
     */
    private static <T> void cleanupOnFailure(Path tempDir, Path targetDir, T newKey) {
        // 1. 清理临时目录
        if (tempDir != null && Files.exists(tempDir)) {
            try {
                deleteDirectoryRecursively(tempDir);
                log.debug("Cleaned up temporary directory: {}", tempDir);
            } catch (IOException e) {
                log.warn("Failed to cleanup temporary directory {}: {}", tempDir, e.getMessage());
            }
        }

        // 2. 清理部分创建的目标目录（如果移动失败但部分文件已存在）
        if (targetDir != null && Files.exists(targetDir)) {
            try {
                // 检查目录是否看起来不完整
                if (isIncompleteKeyDirectory(targetDir)) {
                    log.warn("Detected incomplete key directory, cleaning up: {}", targetDir);
                    deleteDirectoryRecursively(targetDir);
                }
            } catch (IOException e) {
                log.warn("Failed to cleanup target directory {}: {}", targetDir, e.getMessage());
            }
        }

        // 3. 清理密钥资源（如果有资源清理方法）
        if (newKey != null) {
            cleanupKeyResource(newKey);
        }
    }

    /**
     * 递归删除目录
     */
    private static void deleteDirectoryRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) return;
        // 递归删除目录内容
        try (var paths = Files.walk(dir)) {
            paths.sorted((a, b) -> -a.compareTo(b)) // 逆序，先删除文件再删除目录
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            log.warn("Failed to delete {}: {}", path, e.getMessage());
                        }
                    });
        }
    }

    /**
     * 检查目录是否不完整
     */
    private static boolean isIncompleteKeyDirectory(Path dir) {
        try {
            // 简单检查：目录为空或缺少关键文件
            if (!Files.isDirectory(dir)) return false;

            try (var stream = Files.list(dir)) {
                long fileCount = stream.count();
                // 如果目录创建但没有任何密钥文件，可能是不完整的
                return fileCount == 0;
            }
        } catch (IOException e) {
            return true; // 无法访问，认为可能有问题
        }
    }

    /**
     * 清理密钥资源
     */
    private static <T> void cleanupKeyResource(T key) {
        // 这里根据密钥类型进行清理
        if (key instanceof AutoCloseable) {
            try {
                ((AutoCloseable) key).close();
            } catch (Exception e) {
                log.debug("Failed to close key resource: {}", e.getMessage());
            }
        }
    }
}
