package org.springframework.web.bind.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) public @interface PostMapping { String[] value() default {}; }
