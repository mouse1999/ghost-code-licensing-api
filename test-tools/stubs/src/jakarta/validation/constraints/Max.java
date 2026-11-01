package jakarta.validation.constraints; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) public @interface Max { long value() default 0; }
