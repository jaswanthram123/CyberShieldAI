
package com.cybershield.controller;

import com.cybershield.entity.Scan;
import com.cybershield.service.AiEngineService;
import com.cybershield.service.ScanService;
import com.cybershield.service.ScanIndicatorService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/analyze")
public class UrlAnalysisController {

    private final AiEngineService aiEngineService;
    private final ScanService scanService;
    private final ScanIndicatorService scanIndicatorService;

    public UrlAnalysisController(
            AiEngineService aiEngineService,
            ScanService scanService,
            ScanIndicatorService scanIndicatorService
    ) {
        this.aiEngineService = aiEngineService;
        this.scanService = scanService;
        this.scanIndicatorService = scanIndicatorService;
    }

    public record UrlRequest(
            @NotBlank
            @Size(max = 2048)
            String url
    ) {}

    @PostMapping("/url")
    public ResponseEntity<?> analyzeUrl(
            @Valid @RequestBody UrlRequest request
    ) {

        // ---------------------------------------
        // 1. Validate URL
        // ---------------------------------------

        String url = request.url().trim();

        try {
            URI uri = URI.create(url);

            if (!"http".equalsIgnoreCase(uri.getScheme())
                    && !"https".equalsIgnoreCase(uri.getScheme())) {

                return ResponseEntity.badRequest().body(
                        Map.of(
                                "status", "ERROR",
                                "message",
                                "Only HTTP and HTTPS URLs are supported"
                        )
                );
            }

            if (uri.getHost() == null) {

                return ResponseEntity.badRequest().body(
                        Map.of(
                                "status", "ERROR",
                                "message", "Invalid URL hostname"
                        )
                );
            }

        } catch (IllegalArgumentException exception) {

            return ResponseEntity.badRequest().body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Invalid URL format"
                    )
            );
        }

        // ---------------------------------------
        // 2. Call FastAPI URL Analyzer
        // ---------------------------------------

        Map<String, Object> result;

        try {

            result = aiEngineService.analyzeUrl(url);

        } catch (HttpClientErrorException.BadRequest exception) {

            return ResponseEntity.badRequest().body(
                    Map.of(
                            "status", "ERROR",
                            "message",
                            "URL rejected by the AI engine"
                    )
            );

        } catch (RestClientException exception) {

            return ResponseEntity.status(
                    HttpStatus.SERVICE_UNAVAILABLE
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message",
                            "Python AI engine is unavailable"
                    )
            );
        }

        // ---------------------------------------
        // 3. Validate FastAPI Response
        // ---------------------------------------

        if (result == null
                || !"COMPLETED".equals(result.get("status"))
                || !"URL".equals(result.get("scan_type"))
                || !(result.get("risk_score") instanceof Number)
                || !(result.get("risk_level") instanceof String)) {

            return ResponseEntity.status(
                    HttpStatus.BAD_GATEWAY
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message",
                            "AI engine returned an invalid result"
                    )
            );
        }

        // ---------------------------------------
        // 4. Extract Real Detection Indicators
        // ---------------------------------------

        List<String> indicators = new ArrayList<>();

        Object rawIndicators = result.get("indicators");

        if (rawIndicators instanceof List<?> rawList) {

            for (Object item : rawList) {

                if (!(item instanceof String indicator)) {
                    continue;
                }

                String cleaned = indicator.trim();

                if (cleaned.isEmpty()) {
                    continue;
                }

                cleaned = cleaned.substring(
                        0,
                        Math.min(cleaned.length(), 200)
                );

                if (!indicators.contains(cleaned)) {
                    indicators.add(cleaned);
                }

                if (indicators.size() >= 10) {
                    break;
                }
            }
        }

        // ---------------------------------------
        // 5. Save Scan to Supabase
        // ---------------------------------------

        Scan savedScan = scanService.saveUrlScan(
                url,
                result
        );

        // ---------------------------------------
        // 6. Automatically Save Indicators
        // ---------------------------------------

        if (!indicators.isEmpty()) {

            scanIndicatorService.saveIndicators(
                    savedScan.getId(),
                    "URL",
                    indicators
            );
        }

        // ---------------------------------------
        // 7. Return Complete Result to React
        // ---------------------------------------

        Map<String, Object> response =
                new HashMap<>(result);

        response.put(
                "scan_id",
                savedScan.getId()
        );

        response.put(
                "indicators",
                indicators
        );

        response.put(
                "indicator_count",
                indicators.size()
        );

        return ResponseEntity.ok(response);
    }
}
