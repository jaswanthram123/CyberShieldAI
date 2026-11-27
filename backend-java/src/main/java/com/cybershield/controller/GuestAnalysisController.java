
package com.cybershield.controller;

import com.cybershield.service.AiEngineService;
import com.cybershield.service.AiExplanationService;
import com.cybershield.service.GuestRateLimitService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/guest")
public class GuestAnalysisController {

    private static final long TOKEN_SECONDS = 600;
    private static final int MAX_ACTIVE_RESULTS = 200;

    private static final long MAX_GUEST_FILE_BYTES =
            2L * 1024 * 1024;

    private final AiEngineService aiEngineService;
    private final AiExplanationService aiExplanationService;
    private final GuestRateLimitService rateLimitService;

    // Temporary memory only. No raw messages, URLs
    // or uploaded file contents are retained here.
    private final Map<String, GuestSnapshot> pendingResults =
            new HashMap<>();

    private record GuestSnapshot(
            String scanType,
            String riskLevel,
            Number riskScore,
            String prediction,
            List<String> indicators,
            Instant expiresAt
    ) {}

    public GuestAnalysisController(
            AiEngineService aiEngineService,
            AiExplanationService aiExplanationService,
            GuestRateLimitService rateLimitService
    ) {
        this.aiEngineService = aiEngineService;
        this.aiExplanationService = aiExplanationService;
        this.rateLimitService = rateLimitService;
    }

    public record GuestMessageRequest(
            @NotBlank
            @Size(max = 2000)
            String message
    ) {}

    public record GuestUrlRequest(
            @NotBlank
            @Size(max = 2048)
            String url
    ) {}

    public record GuestExplanationRequest(
            @NotBlank
            @Size(max = 80)
            String token
    ) {}

    private ResponseEntity<Map<String, Object>> error(
            HttpStatus status,
            String message
    ) {
        return ResponseEntity.status(status).body(
                Map.of(
                        "status", "ERROR",
                        "message", message
                )
        );
    }

    private synchronized void removeExpiredResults() {
        Instant now = Instant.now();

        pendingResults.entrySet().removeIf(
                entry -> !now.isBefore(
                        entry.getValue().expiresAt()
                )
        );
    }

    private List<String> cleanIndicators(Object raw) {
        List<String> cleaned = new ArrayList<>();

        if (!(raw instanceof List<?> values)) {
            return cleaned;
        }

        for (Object value : values) {
            if (cleaned.size() >= 30) {
                break;
            }

            if (value instanceof String text) {
                String indicator = text.trim();

                if (!indicator.isEmpty()) {
                    cleaned.add(
                            indicator.length() > 300
                                    ? indicator.substring(0, 300)
                                    : indicator
                    );
                }
            }
        }

        return cleaned;
    }

    private synchronized String createExplanationToken(
            Map<String, Object> result
    ) {
        removeExpiredResults();

        if (pendingResults.size() >= MAX_ACTIVE_RESULTS) {
            return null;
        }

        String scanType =
                String.valueOf(result.get("scan_type"));

        String riskLevel =
                String.valueOf(result.get("risk_level"));

        if (!List.of("MESSAGE", "URL", "FILE")
                .contains(scanType)) {
            return null;
        }

        if (!List.of("LOW", "MEDIUM", "HIGH")
                .contains(riskLevel)) {
            return null;
        }

        Object rawScore = result.get("risk_score");

        if (!(rawScore instanceof Number score)) {
            return null;
        }

        double numericScore = score.doubleValue();

        if (!Double.isFinite(numericScore)
                || numericScore < 0
                || numericScore > 100) {
            return null;
        }

        Object rawPrediction = result.get("prediction");

        String prediction = rawPrediction instanceof String
                ? (String) rawPrediction
                : "UNKNOWN";

        if (prediction.length() > 100) {
            prediction = prediction.substring(0, 100);
        }

        List<String> indicators =
                cleanIndicators(result.get("indicators"));

        String token = UUID.randomUUID().toString();

        pendingResults.put(
                token,
                new GuestSnapshot(
                        scanType,
                        riskLevel,
                        score,
                        prediction,
                        List.copyOf(indicators),
                        Instant.now().plusSeconds(TOKEN_SECONDS)
                )
        );

        return token;
    }

    private ResponseEntity<?> completedGuestScan(
            Map<String, Object> result,
            String expectedType
    ) {
        if (result == null
                || !"COMPLETED".equals(result.get("status"))
                || !expectedType.equals(result.get("scan_type"))) {
            return error(
                    HttpStatus.BAD_GATEWAY,
                    "Invalid scanner response"
            );
        }

        String token = createExplanationToken(result);

        if (token == null) {
            return error(
                    HttpStatus.BAD_GATEWAY,
                    "Unable to prepare guest explanation"
            );
        }

        Map<String, Object> response =
                new LinkedHashMap<>(result);

        response.remove("scan_id");
        response.remove("id");

        response.put("guest_explanation_token", token);
        response.put("guest_mode", true);
        response.put("saved", false);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/analyze/message")
    public ResponseEntity<?> analyzeGuestMessage(
            @Valid @RequestBody GuestMessageRequest request
    ) {
        if (!rateLimitService.allowScan()) {
            return error(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Guest scan limit reached. Try again later."
            );
        }

        try {
            Map<String, Object> result =
                    aiEngineService.analyzeMessage(
                            request.message().trim()
                    );

            return completedGuestScan(result, "MESSAGE");

        } catch (HttpClientErrorException.BadRequest exception) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "Message rejected by scanner"
            );

        } catch (RestClientException exception) {
            return error(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "AI scanner temporarily unavailable"
            );
        }
    }

    @PostMapping("/analyze/url")
    public ResponseEntity<?> analyzeGuestUrl(
            @Valid @RequestBody GuestUrlRequest request
    ) {
        String url = request.url().trim();

        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();

            if (scheme == null
                    || (!scheme.equalsIgnoreCase("http")
                    && !scheme.equalsIgnoreCase("https"))
                    || uri.getHost() == null
                    || uri.getUserInfo() != null) {
                return error(
                        HttpStatus.BAD_REQUEST,
                        "Enter a valid HTTP or HTTPS URL"
                );
            }

        } catch (IllegalArgumentException exception) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "Invalid URL"
            );
        }

        if (!rateLimitService.allowScan()) {
            return error(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Guest scan limit reached. Try again later."
            );
        }

        try {
            Map<String, Object> result =
                    aiEngineService.analyzeUrl(url);

            return completedGuestScan(result, "URL");

        } catch (HttpClientErrorException.BadRequest exception) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "URL rejected by scanner"
            );

        } catch (RestClientException exception) {
            return error(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "AI scanner temporarily unavailable"
            );
        }
    }

    @PostMapping(
            value = "/analyze/file",
            consumes = "multipart/form-data"
    )
    public ResponseEntity<?> analyzeGuestFile(
            @RequestParam("file") MultipartFile file
    ) {
        if (file.isEmpty()) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "File cannot be empty"
            );
        }

        if (file.getSize() > MAX_GUEST_FILE_BYTES) {
            return error(
                    HttpStatus.PAYLOAD_TOO_LARGE,
                    "Guest file limit is 2 MB"
            );
        }

        String filename = file.getOriginalFilename();

        if (filename == null || filename.isBlank()) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "Filename is required"
            );
        }

        filename = filename.replace("\\", "/");
        filename = filename.substring(
                filename.lastIndexOf("/") + 1
        );

        if (filename.isBlank()
                || filename.equals(".")
                || filename.equals("..")
                || filename.length() > 255) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "Invalid filename"
            );
        }

        if (!rateLimitService.allowScan()) {
            return error(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Guest scan limit reached. Try again later."
            );
        }

        try {
            Map<String, Object> result =
                    aiEngineService.analyzeFile(
                            filename,
                            file.getBytes()
                    );

            return completedGuestScan(result, "FILE");

        } catch (HttpClientErrorException exception) {
            return error(
                    HttpStatus.BAD_REQUEST,
                    "File rejected by scanner"
            );

        } catch (IOException exception) {
            return error(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Unable to read uploaded file"
            );

        } catch (RestClientException exception) {
            return error(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "AI scanner temporarily unavailable"
            );
        }
    }

    @PostMapping("/explain")
    public ResponseEntity<?> explainGuestScan(
            @Valid @RequestBody GuestExplanationRequest request
    ) {
        String token = request.token();
        GuestSnapshot snapshot;

        synchronized (this) {
            removeExpiredResults();

            snapshot = pendingResults.get(token);

            if (snapshot == null) {
                return error(
                        HttpStatus.BAD_REQUEST,
                        "Explanation token is invalid, expired or already used"
                );
            }

            // Reserve the token before database rate-limit check.
            // Other requests cannot reuse it concurrently.
            pendingResults.remove(token);
        }

        boolean allowed;

        try {
            allowed = rateLimitService.allowExplanation();
        } catch (RuntimeException exception) {
            // Database temporarily unavailable:
            // restore token so the guest can retry.
            restoreToken(token, snapshot);
            throw exception;
        }

        if (!allowed) {
            restoreToken(token, snapshot);

            return error(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Guest AI explanation limit reached. Try again later."
            );
        }

        Map<String, Object> response =
                aiExplanationService.explainGuestAnalysis(
                        snapshot.scanType(),
                        snapshot.riskLevel(),
                        snapshot.riskScore(),
                        snapshot.prediction(),
                        snapshot.indicators()
                );

        return ResponseEntity.ok(response);
    }

    private synchronized void restoreToken(
            String token,
            GuestSnapshot snapshot
    ) {
        if (Instant.now().isBefore(snapshot.expiresAt())) {
            pendingResults.putIfAbsent(token, snapshot);
        }
    }
}
