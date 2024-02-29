import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Input

import java.security.MessageDigest
import java.util.jar.JarFile
import java.util.regex.Pattern

class DuplicateClassFinder extends DefaultTask {
    private static Pattern semver = Pattern.compile("([0-9]+\\.[0-9]+\\.[0-9]+\\-SNAPSHOT)|([0-9]+\\.[0-9]+\\.[0-9]+)");
    private static Pattern product = Pattern.compile("^([a-z0-9a-z]+\\-[a-zA-Z0-9]+)");

    static Map<String, Map<String, File>> buildChangeMap(String directory) {
        var jars = new ArrayList<File>();
        scanForJars(new File(directory), jars);

        // version -> product -> type
        var versionMap = new TreeMap<String, Map<String, Map<String, File>>>();

        jars.each { it ->
            var fileName = it.getName();
            var matcher = semver.matcher(fileName);
            if (!matcher.find()) {
                return
            }
            var semver = matcher.group();

            matcher = product.matcher(fileName);
            if (!matcher.find()) {
                return;
            }
            var prodName = matcher.group();

            var type = "classes";
            if (fileName.contains("source")) {
                type = "source";
            } else if (fileName.contains("javadoc")) {
                type = "javadoc";
            }

            if (!versionMap.containsKey(semver)) {
                versionMap.put(semver, new TreeMap<String, Map<String, Map<String, File>>>())
            }

            var productMap = versionMap.get(semver);
            if (!productMap.containsKey(prodName)) {
                productMap.put(prodName, new TreeMap<String, File>());
            }
            var typeMap = productMap.get(prodName);
            typeMap.put(type, it);

        }


        return versionMap;
    }

    private static void scanForJars(File f, List<File> accumulator) {
        if (f.isDirectory()) {
            var files = f.listFiles();
            if (files != null) {
                files.each { scanForJars(it, accumulator) }
            }
        } else {
            if (f.name.endsWith(".jar")) {
                accumulator.add(f);
            }
        }
    }


    @Input
    String jarDir = "../bc-lts-java-jars/"

    @Input
    Set<String> ignore = new HashSet<>();

    @Input
    boolean verbose = false


    @TaskAction
    def scan() {
        var jarMap = buildChangeMap(jarDir);
        var versions = jarMap.keySet().toList();
        Collections.sort(versions, new Comparator<String>() {
            @Override
            int compare(String o1, String o2) {
                // Snap shot to snapshot
                if (o1.endsWith("-SNAPSHOT") && o2.endsWith("-SNAPSHOT")) {
                    return o1.compareTo(o2);
                } else if (o1.endsWith("-SNAPSHOT")) {
                    o1 = o1.replace("-SNAPSHOT", "");
                    int j = o1.compareTo(o2);
                    if (j == 0) {
                        j = -1
                    }
                    return j
                } else if (o2.endsWith("-SNAPSHOT")) {
                    o2 = o2.replace("-SNAPSHOT", "");
                    int j = o1.compareTo(o2);
                    if (j == 0) {
                        j = 1
                    }
                    return j
                }
                return o1.compareTo(o2);
            }
        })

        var lastVersion = versions.last();
        var classHashToProduct = new HashMap<String, String>();
        var classHashes = new HashMap<String, String>();

        var fail = false;

        jarMap.get(lastVersion).each { entry ->


            var product = entry.key;
            var classesJar = entry.value["classes"]

            println("Scanning: ${((File)classesJar).getName()}")


            var jf = new JarFile((File) classesJar);
            jf.entries().each {
                if (it.name.startsWith("META-INF") || !it.name.endsWith(".class")) {
                    return
                }

                var name = it.name
                        .replace(".class", "")
                        .replace("/", ".");

                var hash = takeHash(jf.getInputStream(it))

                if (classHashes.containsKey(name)) {
                    // Check the digest is the same.
                    if (hash.equals(classHashes.get(name))) {
                        var firstEncountered = classHashToProduct.get(hash);
                        var key = new String("${firstEncountered}:${product}");
                        if (!ignore.contains(key)) {
                            println("$name from $firstEncountered found in $product")
                            fail = true;
                        }
                    }
                } else {
                    classHashToProduct.put(hash, product);
                    classHashes.put(name, hash);
                }

            }

            if (fail) {
                throw new GradleException("Duplicate classes found.")
            }
        }

    }


    static def String takeHash(InputStream src) {
        byte[] b = new byte[65536];
        int l = 0;
        MessageDigest md = MessageDigest.getInstance("SHA256");
        while ((l = src.read(b)) > -1) {
            md.update(b, 0, l);
        }
        src.close();
        return new BigInteger(1, md.digest()).toString(16);
    }
}
