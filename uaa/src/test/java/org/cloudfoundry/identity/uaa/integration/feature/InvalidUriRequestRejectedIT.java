package org.cloudfoundry.identity.uaa.integration.feature;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.xmlunit.assertj.XmlAssert;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = InvalidUriRequestRejectedIT.TestConfig.class)
class InvalidUriRequestRejectedIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Value("${integration.test.base_url}")
    private String baseUrl;

    @Test
    void encodedRandomUriIsReportedAsBadRequest() throws IOException {
        String body = callErrorPageAndCheckHttpStatusCode("/go.php%3Fhttp://interact.sh", 400);
        XmlAssert.assertThat(body)
                .hasXPath("//h2")
                .extractingText()
                .contains("The request was rejected because it contained a potentially malicious character.");
    }

    private String callErrorPageAndCheckHttpStatusCode(String errorPath, int codeExpected) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl + errorPath).openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "text/html");
        connection.connect();
        assertThat(connection.getResponseCode())
                .as("Check status code from " + errorPath + " is " + codeExpected)
                .isEqualTo(codeExpected);
        return getResponseBody(connection);
    }

    private String getResponseBody(HttpURLConnection connection) throws IOException {
        BufferedReader reader;
        if (200 <= connection.getResponseCode() && connection.getResponseCode() <= 299) {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }

        StringBuilder body = new StringBuilder();
        char[] buffer = new char[4096];
        int charsRead;
        try {
            while ((charsRead = reader.read(buffer, 0, buffer.length)) != -1) {
                body.append(buffer, 0, charsRead);
            }
        } catch (IOException ex) {
            IOUtils.close(connection);
        }
        return body.toString();
    }

    @PropertySource("classpath:integration.test.properties")
    static class TestConfig {
        @Bean
        static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
            return new PropertySourcesPlaceholderConfigurer();
        }

        @Bean
        IntegrationTestExtension integrationTestExtension(
                @Value("${integration.test.base_url}") String baseUrl) {
            return new IntegrationTestExtension(baseUrl);
        }
    }
}

