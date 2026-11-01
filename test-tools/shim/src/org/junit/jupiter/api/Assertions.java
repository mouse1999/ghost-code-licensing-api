package org.junit.jupiter.api;
import org.junit.jupiter.api.function.Executable;
import java.util.Objects;
/** Local stand-in for the subset of the JUnit 5 Assertions API used by the tests (NOT part of the module). */
public final class Assertions {
    private Assertions() {}
    public static void assertTrue(boolean c) { if (!c) throw new AssertionError("expected true"); }
    public static void assertTrue(boolean c, String m) { if (!c) throw new AssertionError(m); }
    public static void assertFalse(boolean c) { if (c) throw new AssertionError("expected false"); }
    public static void assertFalse(boolean c, String m) { if (c) throw new AssertionError(m); }
    public static void assertNull(Object o) { if (o != null) throw new AssertionError("expected null but was " + o); }
    public static void assertNotNull(Object o) { if (o == null) throw new AssertionError("expected non-null"); }
    public static void assertNull(Object o, String m) { if (o != null) throw new AssertionError(m + ": expected null but was " + o); }
    public static void assertNotNull(Object o, String m) { if (o == null) throw new AssertionError(m + ": expected non-null"); }
    public static void assertEquals(Object e, Object a) { if (!Objects.equals(e, a)) throw new AssertionError("expected <" + e + "> but was <" + a + ">"); }
    public static void assertEquals(Object e, Object a, String m) { if (!Objects.equals(e, a)) throw new AssertionError(m + " ==> expected <" + e + "> but was <" + a + ">"); }
    public static void assertEquals(long e, long a) { if (e != a) throw new AssertionError("expected <" + e + "> but was <" + a + ">"); }
    public static void assertEquals(long e, long a, String m) { if (e != a) throw new AssertionError(m + " ==> expected <" + e + "> but was <" + a + ">"); }
    public static void assertNotEquals(Object u, Object a) { if (Objects.equals(u, a)) throw new AssertionError("expected different values but both were <" + a + ">"); }
    public static void assertNotEquals(Object u, Object a, String m) { if (Objects.equals(u, a)) throw new AssertionError(m + " ==> expected different values but both were <" + a + ">"); }
    public static void assertSame(Object e, Object a) { if (e != a) throw new AssertionError("expected same instance"); }
    public static void fail(String m) { throw new AssertionError(m); }
    public static void assertArrayEquals(byte[] e, byte[] a) { if (!java.util.Arrays.equals(e, a)) throw new AssertionError("arrays differ"); }
    public static void assertDoesNotThrow(Executable x) {
        try { x.execute(); } catch (Throwable t) { throw new AssertionError("unexpected exception: " + t, t); }
    }
    public static <T extends Throwable> T assertThrows(Class<T> type, Executable x) {
        try { x.execute(); } catch (Throwable t) {
            if (type.isInstance(t)) return type.cast(t);
            throw new AssertionError("expected " + type.getName() + " but got " + t, t);
        }
        throw new AssertionError("expected " + type.getName() + " but nothing was thrown");
    }
    public static <T extends Throwable> T assertThrows(Class<T> type, Executable x, String m) {
        try { return assertThrows(type, x); } catch (AssertionError e) { throw new AssertionError(m + " ==> " + e.getMessage(), e); }
    }
    public static void assertDoesNotThrow(Executable x, String m) {
        try { assertDoesNotThrow(x); } catch (AssertionError e) { throw new AssertionError(m + " ==> " + e.getMessage(), e); }
    }
}
