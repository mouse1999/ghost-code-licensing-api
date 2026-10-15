package com.interviewassistant.licensing.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** Entry point of the standalone licensing API. Independent of the desktop application. */
@SpringBootApplication(scanBasePackages = "com.interviewassistant.licensing.web")
@ConfigurationPropertiesScan(basePackages = "com.interviewassistant.licensing.web")
public class LicensingApplication {

    public static void main(String[] args) {
        SpringApplication.run(LicensingApplication.class, args);
    }
}
