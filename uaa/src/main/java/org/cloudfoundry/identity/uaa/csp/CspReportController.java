package org.cloudfoundry.identity.uaa.csp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
@RequestMapping("/api/csp-reports")
public class CspReportController {
    private static final Logger logger = LoggerFactory.getLogger(CspReportController.class);

    @PostMapping
    public void receiveCspReport(@RequestBody Map<String, Object> report, HttpServletResponse response) {
        logger.warn("Received CSP violation report: {}", report);
        response.setStatus(HttpStatus.NO_CONTENT.value());
    }
}