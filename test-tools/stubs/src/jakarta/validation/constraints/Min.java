package jakarta.validation.constraints; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) public @interface Min { long value() default 0; }
