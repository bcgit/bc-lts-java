import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import org.gradle.api.Project

import java.util.logging.FileHandler

class ExtraFunctions {

    static def directoryExists(String path) {
        return new File(path).isDirectory();
    }


    /**
     * Copy content of a one directory to another.
     * @param sourceDir
     * @param destinationDir
     */
    static def copyDirContent(String sourceDir, String destinationDir) {

        File[] files = Paths.get(sourceDir).toFile().listFiles();
        File dest = new File(destinationDir);
        if (!dest.exists()) {
            if (!dest.mkdirs()) {
                throw new RuntimeException("could not create " + dest);
            }
        }

        for (File f : files) {
            Files.copy(Paths.get(f.getPath()), Paths.get(destinationDir, f.getName()), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    static File copyFile(String srcFile, String destinationDir) {
        File f = new File(srcFile);
        if (f.exists()) {
            Files.copy(Paths.get(f.getPath()), Paths.get(destinationDir, f.getName()), StandardCopyOption.REPLACE_EXISTING);
        } else {
            System.out.println("$f did not exist");
        }

        return f;
    }


    static def ifTrue(Project project, String propertyName, Runnable then) {
        String value = project.findProperty(propertyName);
        if ("true".equals(value)) {
            then()
        }
    }

    static def os() {
        String os_ = System.getProperty("os.name", "").toLowerCase();
        if (os_.contains("darwin") || os_.contains("mac os")) {
            return "darwin";
        } else if (os_.contains("linux")) {
            return "linux";
        }

        throw new IllegalStateException("$os_ not supported.");
    }


    /**
     * Whether this host's CPU can run a native variant. The per-variant requirements mirror the
     * probe's own table, as printed by 'DumpInfo -a': avx needs avx, vaes needs vaes, and vaesf
     * additionally needs avx512f, avx512bw and vpclmulqdq.
     * <p>
     * Forcing a variant the CPU cannot execute does not fail cleanly - the JVM takes an illegal
     * instruction and dumps core - so the variant test tasks gate on this and skip instead. When the
     * flags cannot be read the answer is 'true': leaving a task enabled surfaces a problem, whereas
     * silently skipping hides the coverage.
     */
    static boolean cpuSupportsVariant(String variant) {
        if (variant == null || variant.isEmpty() || "java".equals(variant) || "auto".equals(variant)) {
            return true;
        }

        // ASIMD is mandatory on ARMv8-A, and the neon-le tasks are only registered on aarch64.
        if ("neon-le".equals(variant)) {
            return true;
        }

        Set<String> flags = cpuFlags();
        if (flags.isEmpty()) {
            return true;
        }

        switch (variant) {
            case "avx":
                return flags.contains("avx");
            case "vaes":
                return flags.contains("vaes");
            case "vaesf":
                return flags.contains("vaes") && flags.contains("avx512f") &&
                        flags.contains("avx512bw") && flags.contains("vpclmulqdq");
            default:
                return true;
        }
    }

    /**
     * The host CPU feature flags, lower-cased, or an empty set when they cannot be determined.
     */
    static Set<String> cpuFlags() {
        try {
            if ("linux".equals(os())) {
                File cpuinfo = new File("/proc/cpuinfo");
                if (!cpuinfo.exists()) {
                    return Collections.emptySet();
                }
                Set<String> found = new HashSet<String>();
                cpuinfo.eachLine { String line ->
                    // x86 reports 'flags', aarch64 reports 'Features'
                    if (line.startsWith("flags") || line.startsWith("Features")) {
                        int colon = line.indexOf((int)(':' as char));
                        if (colon >= 0) {
                            found.addAll(line.substring(colon + 1).trim().toLowerCase().split("\\s+") as List);
                        }
                    }
                }
                return found;
            }

            // darwin
            Set<String> found = new HashSet<String>();
            for (String key : ["machdep.cpu.features", "machdep.cpu.leaf7_features"]) {
                Process p = ["sysctl", "-n", key].execute();
                p.waitFor();
                found.addAll(p.text.trim().toLowerCase().split("\\s+") as List);
            }
            return found;
        } catch (Exception ignored) {
            return Collections.emptySet();
        }
    }


    /**
     * Fetches a test property value of the following format
     * 'testing.<taskName>.<os>.<arch>.<id>'
     *
     * Will try wildcard variants, without taskName and os are supported
     *  'testing.anyTask.anyOs.id' are also supported
     *
     * @param project The project
     * @param task the task
     * @param id the id
     * @return the value
     */
    static def String testValue(Project project, String task, String arch, String id) {


        def tasks = [task, "anyTask"];
        def archs = arch != null ? [arch, "anyArch"] : ["anyArch"]
        def os = [os(), "anyOs"]

        for (String t : tasks) {
            for (String o : os) {
                for (String a : archs) {
                    String name = "testing.${t}.${o}.${a}.${id}";
                    String result = project.findProperty(name);

                    if (result != null) {
                        println("Found $name => $result");
                        return result;
                    }
                }
            }
        }

        return null;
    }

    static String propValsAsArgs(Project project, String task, String id, String arg) {
        propValsAsArgs(project, task, null, id, arg)
    }

    static String propValsAsArgs(Project project, String task, String arch, String id, String arg) {
        def val = testValue(project, task, arch, id);
        (val != null) ? "-D$arg=$val" : ""
    }

    static boolean hasPropVal(Project project, String task, String arch, String id, String arg) {
        def val = testValue(project, task, arch, id);
        return val != null
    }


    static String propValOrFail(Project project, String task, String arch, String id) {
        def val = testValue(project, task, arch, id);
        if (val == null) {
            throw new IllegalStateException("prop testing.${task}.${arch}.${id} was not found");
        }
        val
    }

    static void removeTempFileNix(String dir) {
        if (dir.equals("")) {
            return
        }


        File root = new File(dir);
        String tmp = new File(System.getProperty("java.io.tmpdir")).getCanonicalPath();

        if (!root.exists()) {
            System.out.println("${root.getCanonicalPath()} does not exist");
        }

        if (!root.isDirectory()) {
            System.out.println("${root.getCanonicalPath()} is not directory");
        }


        for (File f : root.listFiles()) {
            f.delete();
        }
    }

    static void installDeps(List<String> variants, String src_, String dest_) {
        File srcDir = new File(src_);
        File destDir = new File(dest_);

        File depFile = new File(srcDir, "deps.list");
        if (!depFile.exists()) {
            return; // no deps
        }
        // Copy dep file.
        Files.copy(depFile.toPath(), new File(destDir, depFile.name).toPath(), StandardCopyOption.REPLACE_EXISTING);

        Set<String> variantSet = variants.toSet();
        Files.readAllLines(depFile.toPath()).each { it ->
            String[] parts = it.split(":");
            if (variantSet.contains(parts[0])) {
                Files.copy(new File(srcDir, parts[1]).toPath(), new File(destDir, parts[1]).toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        }

    }

    static void scanAndAddFilename(List<String> names, String dir, String endsWith) {
        File srcDir = new File(dir);
        if (srcDir.exists() && srcDir.isDirectory()) {
            for (File file : srcDir.listFiles()) {
                if (file.name.endsWith(endsWith)) {
                    names.add(file.name);
                }
            }
        }
    }


}
