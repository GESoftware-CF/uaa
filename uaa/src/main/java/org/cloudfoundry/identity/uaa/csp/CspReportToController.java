package org.cloudfoundry.identity.uaa.csp;

import org.cloudfoundry.identity.uaa.csp.CspReportToPayload;
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
import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor // Generates a constructor with ObjectMapper
public class CspReportToController {

    private static final Logger logger = LoggerFactory.getLogger(CspReportToController.class);
    private final ObjectMapper objectMapper; // Injected to convert payload to JSON string

    @PostMapping(
            value = "/csp-reports",
            consumes = {MediaType.APPLICATION_JSON_VALUE, "application/reports+json"}
    )
    public ResponseEntity<Void> handleCspReports(
            @RequestBody List<CspReportToPayload> reportsPayload,
            HttpServletRequest request) {

        logger.warn("Received CSP Report-To Violation from {}. Total reports: {}",
                request.getRemoteAddr(),
                reportsPayload != null ? reportsPayload.size() : 0);

        if (reportsPayload != null) {
            for (CspReportToPayload report : reportsPayload) {
                String rawPayloadString = "";
                try {
                    // Convert the received POJO back to a JSON string for display/logging
                    rawPayloadString = objectMapper.writeValueAsString(report);
                    // >>>>>>> OUTPUTTING THE PAYLOAD IN JSON FORMAT TO CONSOLE <<<<<<<<<
                    logger.info("CSP Report-To Payload (JSON): {}", rawPayloadString);
                } catch (JsonProcessingException e) {
                    logger.error("Error converting report-to payload POJO to JSON string: {}", e.getMessage());
                    rawPayloadString = "Error converting payload: " + e.getMessage();
                }

                // You can still log parsed details if needed, even without Splunk
                if ("csp-violation".equals(report.getType()) && report.getBody() != null) {
                    CspReportToPayload.Body body = report.getBody();
                    logger.debug("  Parsed Report-To Details: Doc URL='{}', Violated Directive='{}', Blocked URL='{}'",
                            body.getDocumentUrl(), body.getViolatedDirective(), body.getBlockedURL());
                } else {
                    logger.warn("  Received non-CSP or malformed report-to payload. Type={}", report.getType());
                }
            }
        } else {
            logger.error("Received null or empty CSP Report-To payload.");
        }

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}