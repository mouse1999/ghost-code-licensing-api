package minirunner;
import org.junit.jupiter.api.*;
import java.io.File;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
/** Runs classes containing @Test methods from a compiled test directory; prints pass/fail counts. */
public final class MiniRunner {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]);
        String filter = args.length > 1 ? args[1] : "";
        List<String> classes = new ArrayList<>();
        try (var w = Files.walk(root)) {
            w.filter(p -> p.toString().endsWith("Test.class") || p.toString().endsWith("IT.class")).forEach(p ->
                classes.add(root.relativize(p).toString().replace(File.separatorChar, '.').replaceAll("\\.class$", "")));
        }
        Collections.sort(classes);
        int pass = 0, fail = 0; List<String> failures = new ArrayList<>();
        for (String cn : classes) {
            if (!cn.contains(filter)) continue;
            Class<?> c = Class.forName(cn);
            if (Modifier.isAbstract(c.getModifiers())) continue;
            List<Method> tests = new ArrayList<>(), before = new ArrayList<>(), after = new ArrayList<>();
            for (Method m : c.getDeclaredMethods()) {
                m.setAccessible(true);
                if (m.isAnnotationPresent(Test.class)) tests.add(m);
                if (m.isAnnotationPresent(BeforeEach.class)) before.add(m);
                if (m.isAnnotationPresent(AfterEach.class)) after.add(m);
            }
            tests.sort(Comparator.comparing(Method::getName));
            for (Method t : tests) {
                Constructor<?> k = c.getDeclaredConstructor(); k.setAccessible(true);
                Object o = k.newInstance();
                String id = c.getSimpleName() + "." + t.getName();
                try {
                    for (Method b : before) b.invoke(o);
                    try { t.invoke(o); } finally { for (Method a : after) a.invoke(o); }
                    pass++; System.out.println("PASS  " + id);
                } catch (InvocationTargetException e) {
                    fail++; Throwable cause = e.getCause(); failures.add(id + ": " + cause);
                    System.out.println("FAIL  " + id + "  -> " + cause);
                    if (System.getenv("MINI_TRACE") != null) cause.printStackTrace(System.out);
                }
            }
        }
        System.out.println("\n==== " + (pass + fail) + " tests, " + pass + " passed, " + fail + " failed ====");
        for (String f : failures) System.out.println("  " + f);
        System.exit(fail == 0 ? 0 : 1);
    }
}
