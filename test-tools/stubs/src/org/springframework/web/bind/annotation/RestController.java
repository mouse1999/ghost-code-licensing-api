package org.springframework.web.bind.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) public @interface RestController { String[] value() default {}; }
