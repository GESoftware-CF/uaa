package org.cloudfoundry.identity.uaa.csp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/csp-reports")
public class CspReportController {
    private static final Logger logger = LoggerFactory.getLogger(CspReportController.class);

    @PostMapping
    public ResponseEntity<Void> handleCspReportUri(
            @RequestBody Map<String, Object> cspReportPayload, // Map<String, Object> to parse general JSON
            HttpServletRequest request) {

        logger.warn("Received CSP report-uri Violation from {}: {}",
                request.getRemoteAddr(),
                cspReportPayload);

        // The 'csp-report' key contains the actual violation details
        Map<String, Object> cspReport = (Map<String, Object>) cspReportPayload.get("csp-report");

        if (cspReport != null) {
            String documentUri = (String) cspReport.get("document-uri");
            String violatedDirective = (String) cspReport.get("violated-directive");
            String blockedUri = (String) cspReport.get("blocked-uri");
            String originalPolicy = (String) cspReport.get("original-policy");

            logger.warn("CSP Violation Details: Doc URI='{}', Violated Directive='{}', Blocked URI='{}', Policy='{}'",
                    documentUri, violatedDirective, blockedUri, originalPolicy);

            // TODO: Here's where you'd implement your persistent storage logic:
            // - Save to a database (e.g., using Spring Data JPA)
            // - Append to a dedicated log file
            // - Send to a log aggregation system (Splunk, ELK, etc.)
            // - Trigger alerts for critical or frequent violations
        } else {
            logger.error("Received malformed CSP report-uri payload: 'csp-report' key missing.");
        }

        // Return 204 No Content, indicating successful receipt without a response body.
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}