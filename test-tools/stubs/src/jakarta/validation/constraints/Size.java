package jakarta.validation.constraints; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) public @interface Size { int max() default 2147483647; int min() default 0; }
