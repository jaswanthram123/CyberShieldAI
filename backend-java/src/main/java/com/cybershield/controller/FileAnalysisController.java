
package com.cybershield.controller;

import com.cybershield.entity.Scan;
import com.cybershield.service.AiEngineService;
import com.cybershield.service.ScanService;
import com.cybershield.service.ScanIndicatorService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/analyze")
public class FileAnalysisController {

    private static final long MAX_FILE_SIZE =
            10L * 1024 * 1024;

    private final AiEngineService aiEngineService;
    private final ScanService scanService;
    private final ScanIndicatorService scanIndicatorService;

    public FileAnalysisController(
            AiEngineService aiEngineService,
            ScanService scanService,
            ScanIndicatorService scanIndicatorService
    ) {
        this.aiEngineService = aiEngineService;
        this.scanService = scanService;
        this.scanIndicatorService = scanIndicatorService;
    }

    @PostMapping(
            value = "/file",
            consumes = "multipart/form-data"
    )
    public ResponseEntity<?> analyzeFile(
            @RequestParam("file") MultipartFile file
    ) {

        // ---------------------------------------
        // 1. Validate uploaded file
        // ---------------------------------------

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(
                    Map.of(
                            "status", "ERROR",
                            "message", "File cannot be empty"
                    )
            );
        }

        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.status(
                    HttpStatus.PAYLOAD_TOO_LARGE
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Maximum file size is 10 MB"
                    )
            );
        }

        String filename = file.getOriginalFilename();

        if (filename == null || filename.isBlank()) {
            return ResponseEntity.badRequest().body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Filename is required"
                    )
            );
        }

        filename = filename.replace("\\", "/");

        filename = filename.substring(
                filename.lastIndexOf("/") + 1
        );

        if (filename.isBlank()
                || filename.equals(".")
                || filename.equals("..")) {

            return ResponseEntity.badRequest().body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Invalid filename"
                    )
            );
        }

        // ---------------------------------------
        // 2. Call Python file analyzer
        // ---------------------------------------

        Map<String, Object> result;

        try {
            result = aiEngineService.analyzeFile(
                    filename,
                    file.getBytes()
            );

        } catch (HttpClientErrorException exception) {

            return ResponseEntity.status(
                    exception.getStatusCode()
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message", "File rejected by AI engine"
                    )
            );

        } catch (RestClientException exception) {

            return ResponseEntity.status(
                    HttpStatus.SERVICE_UNAVAILABLE
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Python AI engine is unavailable"
                    )
            );

        } catch (IOException exception) {

            return ResponseEntity.status(
                    HttpStatus.INTERNAL_SERVER_ERROR
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Unable to read uploaded file"
                    )
            );
        }

        // ---------------------------------------
        // 3. Validate FastAPI response
        // ---------------------------------------

        if (result == null
                || !"COMPLETED".equals(result.get("status"))
                || !"FILE".equals(result.get("scan_type"))
                || !(result.get("risk_score") instanceof Number)
                || !(result.get("risk_level") instanceof String)) {

            return ResponseEntity.status(
                    HttpStatus.BAD_GATEWAY
            ).body(
                    Map.of(
                            "status", "ERROR",
                            "message", "Invalid AI engine response"
                    )
            );
        }

        // ---------------------------------------
        // 4. Extract actual scan indicators
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
        // 5. Save scan metadata
        // ---------------------------------------

        Scan savedScan = scanService.saveFileScan(
                filename,
                result
        );

        // ---------------------------------------
        // 6. Save detected indicators
        // ---------------------------------------

        if (!indicators.isEmpty()) {

            scanIndicatorService.saveIndicators(
                    savedScan.getId(),
                    "FILE",
                    indicators
            );
        }

        // ---------------------------------------
        // 7. Prepare frontend response
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
