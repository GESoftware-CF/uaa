package org.cloudfoundry.identity.uaa.csp;

import org.cloudfoundry.identity.uaa.csp.CspReportUriPayload;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor; // Used by Lombok for constructor injection
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor // Generates a constructor with ObjectMapper
public class CspReportUriController {

    private static final Logger logger = LoggerFactory.getLogger(CspReportUriController.class);
    private final ObjectMapper objectMapper; // Injected to convert payload to JSON string

    @PostMapping(value = "/csp-report-uri", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> handleCspReportUri(
            @RequestBody CspReportUriPayload cspReportPayload,
            HttpServletRequest request) {

        String rawPayloadString = "";
        try {
            // Convert the received POJO back to a JSON string for display/logging
            rawPayloadString = objectMapper.writeValueAsString(cspReportPayload);
            // >>>>>>> OUTPUTTING THE PAYLOAD IN JSON FORMAT TO CONSOLE <<<<<<<<<
            logger.info("CSP Report-URI Payload (JSON): {}", rawPayloadString);
        } catch (JsonProcessingException e) {
            logger.error("Error converting report-uri payload POJO to JSON string: {}", e.getMessage());
            rawPayloadString = "Error converting payload: " + e.getMessage();
        }

        // You can still log parsed details if needed, even without Splunk
        if (cspReportPayload.getCspReport() != null) {
            CspReportUriPayload.CspReportUriDetails details = cspReportPayload.getCspReport();
            logger.debug("  Parsed Report-URI Details: Doc URI='{}', Violated Directive='{}', Blocked URI='{}'",
                    details.getDocumentUri(), details.getViolatedDirective(), details.getBlockedUri());
        } else {
            logger.error("Received malformed CSP report-uri payload: 'csp-report' key missing or null.");
        }

        // No Splunk integration here, simply acknowledge receipt
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}