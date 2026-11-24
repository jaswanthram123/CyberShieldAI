
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
import org.springframework.web.client.RestClientException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/analyze")
@CrossOrigin(origins = "http://localhost:5173")
public class MessageAnalysisController {

    private final AiEngineService aiEngineService;
    private final ScanService scanService;
    private final ScanIndicatorService scanIndicatorService;

    public MessageAnalysisController(
            AiEngineService aiEngineService,
            ScanService scanService,
            ScanIndicatorService scanIndicatorService
    ) {
        this.aiEngineService = aiEngineService;
        this.scanService = scanService;
        this.scanIndicatorService = scanIndicatorService;
    }

    public record MessageRequest(
            @NotBlank
            @Size(max = 10000)
            String message
    ) {}

    @PostMapping("/message")
    public ResponseEntity<?> analyzeMessage(
            @Valid @RequestBody MessageRequest request
    ) {

        // ---------------------------------------
        // 1. Analyze message using FastAPI
        // ---------------------------------------

        Map<String, Object> result;

        try {
            result = aiEngineService.analyzeMessage(
                    request.message()
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
        // 2. Validate FastAPI response
        // ---------------------------------------

        if (result == null
                || !"COMPLETED".equals(result.get("status"))
                || !"MESSAGE".equals(result.get("scan_type"))
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
        // 3. Extract actual message indicators
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
        // 4. Save message scan to Supabase
        // ---------------------------------------

        Scan savedScan = scanService.saveMessageScan(
                request.message(),
                result
        );

        // ---------------------------------------
        // 5. Automatically save indicators
        // ---------------------------------------

        if (!indicators.isEmpty()) {

            scanIndicatorService.saveIndicators(
                    savedScan.getId(),
                    "MESSAGE",
                    indicators
            );
        }

        // ---------------------------------------
        // 6. Return result to React
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
