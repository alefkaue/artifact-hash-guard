import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.util.*;
import java.util.regex.*;

/** Offline SHA-256 manifest verification. Does not modify artifacts. */
public final class ArtifactHashGuard {
    private record Entry(String digest, String name) {}
    private static final Pattern LINE = Pattern.compile("^([a-fA-F0-9]{64})  (.+)$");

    private static List<Entry> manifest(Path path) throws IOException {
        if (Files.size(path) > 1024 * 1024) throw new IllegalArgumentException("Manifest exceeds 1 MiB");
        List<Entry> entries = new ArrayList<>();
        Set<String> names = new HashSet<>();
        int number = 0;
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            number++;
            if (line.isBlank() || line.startsWith("#")) continue;
            Matcher match = LINE.matcher(line);
            if (!match.matches()) throw new IllegalArgumentException("Invalid manifest line " + number);
            String name = match.group(2);
            if (name.startsWith("/") || name.contains("\\") || name.contains(":")
                    || name.chars().anyMatch(c -> c < 32 || c == 127)
                    || Arrays.stream(name.split("/", -1)).anyMatch(p -> p.isEmpty() || p.equals(".") || p.equals("..")))
                throw new IllegalArgumentException("Unsafe path at line " + number);
            if (!names.add(name)) throw new IllegalArgumentException("Duplicate manifest path: " + name);
            entries.add(new Entry(match.group(1).toLowerCase(Locale.ROOT), name));
        }
        if (entries.isEmpty()) throw new IllegalArgumentException("Manifest has no entries");
        return entries;
    }

    private static Path checkedPath(Path root, String name) throws IOException {
        Path current = root;
        for (String part : name.split("/")) {
            current = current.resolve(part);
            if (Files.isSymbolicLink(current)) throw new IOException("Symbolic link rejected: " + name);
        }
        if (!current.normalize().startsWith(root)) throw new IOException("Path escapes root");
        if (Files.exists(current, LinkOption.NOFOLLOW_LINKS) && !current.toRealPath().startsWith(root))
            throw new IOException("Resolved path escapes root: " + name);
        return current;
    }

    private static String digest(Path path) throws IOException, NoSuchAlgorithmException {
        BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile()) throw new IOException("Not a regular file: " + path.getFileName());
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.allocate(65536);
            while (channel.read(buffer) != -1) {
                buffer.flip();
                sha.update(buffer);
                buffer.clear();
            }
        }
        BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
                || !Objects.equals(before.fileKey(), after.fileKey()))
            throw new IOException("File changed while hashing: " + path.getFileName());
        return HexFormat.of().formatHex(sha.digest());
    }

    public static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 1 && args[0].equals("--help")) {
            out.println("Usage: ArtifactHashGuard verify MANIFEST ROOT");
            return 0;
        }
        if (args.length != 3 || !args[0].equals("verify")) {
            err.println("Usage: ArtifactHashGuard verify MANIFEST ROOT");
            return 2;
        }
        try {
            List<Entry> entries = manifest(Path.of(args[1]));
            Path rootInput = Path.of(args[2]).toAbsolutePath().normalize();
            if (Files.isSymbolicLink(rootInput) || !Files.isDirectory(rootInput))
                throw new IOException("Root must be a directory, not a symbolic link");
            Path root = rootInput.toRealPath();
            // Validate every target before hashing, to avoid a partial success report on invalid input.
            List<Path> targets = new ArrayList<>();
            for (Entry entry : entries) targets.add(checkedPath(root, entry.name()));
            int failures = 0;
            for (int i = 0; i < entries.size(); i++) {
                Entry entry = entries.get(i);
                String status;
                try {
                    status = digest(targets.get(i)).equals(entry.digest()) ? "OK" : "MISMATCH";
                } catch (NoSuchFileException missing) {
                    status = "MISSING";
                }
                if (!status.equals("OK")) failures++;
                out.println(status + "\t" + entry.name());
            }
            out.printf(Locale.ROOT, "SUMMARY\tchecked=%d\tfailed=%d%n", entries.size(), failures);
            return failures == 0 ? 0 : 1;
        } catch (IOException | IllegalArgumentException | NoSuchAlgorithmException | UnsupportedOperationException error) {
            err.println("ERROR: " + error.getMessage());
            return 2;
        }
    }

    public static void main(String[] args) { System.exit(run(args, System.out, System.err)); }
}
