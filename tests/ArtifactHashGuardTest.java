import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Dependency-free integration tests, executed with an ordinary JDK. */
public final class ArtifactHashGuardTest {
    private static int checks;
    private static void check(boolean value, String label) {
        checks++;
        if (!value) throw new AssertionError(label);
    }
    private static int run(Path manifest, Path root, String expected) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int code = ArtifactHashGuard.run(new String[]{"verify", manifest.toString(), root.toString()},
                new PrintStream(bytes, true, StandardCharsets.UTF_8), new PrintStream(OutputStream.nullOutputStream()));
        check(bytes.toString(StandardCharsets.UTF_8).contains(expected), "Output contains " + expected);
        return code;
    }
    public static void main(String[] args) throws Exception {
        Path temp = Files.createTempDirectory("artifact-guard-test");
        try {
            Path root = Files.createDirectory(temp.resolve("artifacts"));
            Path manifest = temp.resolve("checksums.sha256");
            Path artifact = root.resolve("demo.txt");
            byte[] data = "example\n".getBytes(StandardCharsets.UTF_8);
            String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
            Files.write(artifact, data);
            Files.writeString(manifest, "# lab\n" + sha + "  demo.txt\n");
            check(run(manifest, root, "OK\tdemo.txt") == 0, "Unchanged artifact");
            Files.writeString(artifact, "changed\n");
            check(run(manifest, root, "MISMATCH\tdemo.txt") == 1, "Tampered artifact");
            Files.delete(artifact);
            check(run(manifest, root, "MISSING\tdemo.txt") == 1, "Missing artifact");
            for (String bad : new String[]{"../escape", "/absolute", "C:/drive", "folder\\file", "a//b", "./file"}) {
                Files.writeString(manifest, sha + "  " + bad + "\n");
                check(run(manifest, root, "") == 2, "Reject unsafe path " + bad);
            }
            Files.writeString(manifest, sha + "  demo.txt\n" + sha + "  demo.txt\n");
            check(run(manifest, root, "") == 2, "Duplicate rejected");
            Files.writeString(manifest, "bad manifest");
            check(run(manifest, root, "") == 2, "Malformed rejected");
            Files.writeString(manifest, "# empty");
            check(run(manifest, root, "") == 2, "Empty rejected");
            Files.writeString(manifest, sha + "  demo.txt\n");
            try {
                Files.createSymbolicLink(artifact, manifest);
                check(run(manifest, root, "") == 2, "Symlink rejected");
            } catch (FileSystemException | UnsupportedOperationException unavailable) {
                System.out.println("SKIP: symlink creation unavailable");
            }
            System.out.println("PASS: " + checks + " assertions");
        } finally {
            try (var paths = Files.walk(temp)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }
}
