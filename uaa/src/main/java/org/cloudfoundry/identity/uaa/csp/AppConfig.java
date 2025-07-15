package org.cloudfoundry.identity.uaa.csp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
public class AppConfig {

    // This ObjectMapper is crucial for converting POJOs to JSON strings for logging
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}