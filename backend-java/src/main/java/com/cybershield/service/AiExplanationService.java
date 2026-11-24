
package com.cybershield.service;

import com.cybershield.entity.Scan;
import com.cybershield.repository.ScanRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;

import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import org.springframework.web.server.ResponseStatusException;

import java.net.http.HttpClient;
import java.time.Duration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AiExplanationService {

    private static final Logger logger =
            LoggerFactory.getLogger(
                    AiExplanationService.class
            );

    private final ScanRepository scanRepository;
    private final ScanIndicatorService scanIndicatorService;
    private final RestClient restClient;

    // ---------------------------------------
    // Constructor
    // ---------------------------------------

    public AiExplanationService(
            ScanRepository scanRepository,
            ScanIndicatorService scanIndicatorService,
            @Value("${ai.engine.url:http://127.0.0.1:8000}")
            String aiEngineUrl
    ) {

        this.scanRepository = scanRepository;
        this.scanIndicatorService = scanIndicatorService;

        // Force HTTP/1.1 for FastAPI compatibility.
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        JdkClientHttpRequestFactory factory =
                new JdkClientHttpRequestFactory(httpClient);

        factory.setReadTimeout(Duration.ofSeconds(190));

        this.restClient = RestClient.builder()
                .baseUrl(aiEngineUrl)
                .requestFactory(factory)
                .build();

        logger.info(
                "AI Explanation Service configured for {}",
                aiEngineUrl
        );
    }

    // ---------------------------------------
    // Generate Explanation for Saved Scan
    // ---------------------------------------

    public Map<String, Object> explainScan(Long scanId) {

        // ---------------------------------------
        // 1. Retrieve Scan from Supabase
        // ---------------------------------------

        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Scan not found"
                        )
                );

        String scanType = scan.getScanType();
        String riskLevel = scan.getRiskLevel();

        // ---------------------------------------
        // 2. Validate Scan
        // ---------------------------------------

        if (!List.of("MESSAGE", "URL", "FILE")
                .contains(scanType)) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported scan type"
            );
        }

        if (!List.of("LOW", "MEDIUM", "HIGH")
                .contains(riskLevel)) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid risk level"
            );
        }

        if (scan.getRiskScore() == null) {

            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Risk score is missing"
            );
        }

        // ---------------------------------------
        // 3. Retrieve Actual Detection Indicators
        // ---------------------------------------

        List<String> indicators =
                scanIndicatorService.getIndicators(scanId);

        logger.info(
                "Found {} indicators for scan {}",
                indicators.size(),
                scanId
        );

        // ---------------------------------------
        // 4. Prepare FastAPI Request
        // ---------------------------------------

        Map<String, Object> request =
                new LinkedHashMap<>();

        request.put("scan_type", scanType);
        request.put("risk_level", riskLevel);
        request.put(
                "risk_score",
                scan.getRiskScore()
        );

        // Prediction is not yet stored as a
        // separate structured database field.
        request.put("prediction", "UNKNOWN");

        // Send actual stored detection indicators.
        // Empty list activates the Python fallback.
        request.put("indicators", indicators);

        logger.info(
                "Requesting AI explanation for scan {}",
                scanId
        );

        // ---------------------------------------
        // 5. Call FastAPI
        // ---------------------------------------

        try {

            Map<?, ?> aiResponse = restClient.post()
                    .uri("/explain")
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(Map.class);

            // ---------------------------------------
            // 6. Validate FastAPI Response
            // ---------------------------------------

            if (aiResponse == null) {

                throw new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "Empty response from AI engine"
                );
            }

            Object status = aiResponse.get("status");
            Object explanation =
                    aiResponse.get("explanation");

            if (!"COMPLETED".equals(status)
                    || !(explanation instanceof String)
                    || ((String) explanation).isBlank()) {

                logger.error(
                        "AI engine returned an incomplete explanation for scan {}",
                        scanId
                );

                throw new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "AI explanation was not completed"
                );
            }

            // ---------------------------------------
            // 7. Prepare Response for React
            // ---------------------------------------

            Map<String, Object> response =
                    new LinkedHashMap<>();

            response.put("scan_id", scan.getId());
            response.put("scan_type", scanType);

            response.put(
                    "risk_level",
                    riskLevel
            );

            response.put(
                    "risk_score",
                    scan.getRiskScore()
            );

            response.put("status", status);

            response.put(
                    "model",
                    aiResponse.get("model")
            );

            response.put(
                    "explanation",
                    explanation
            );

            response.put(
                    "disclaimer",
                    aiResponse.get("disclaimer")
            );

            // Include indicators so the frontend
            // can display the supporting evidence.
            response.put(
                    "indicators",
                    indicators
            );

            logger.info(
                    "AI explanation completed for scan {} using model {}",
                    scanId,
                    aiResponse.get("model")
            );

            return response;

        } catch (RestClientResponseException error) {

            // FastAPI returned an HTTP error.

            logger.error(
                    "FastAPI returned HTTP {} for scan {}",
                    error.getStatusCode().value(),
                    scanId
            );

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "AI engine rejected the explanation request",
                    error
            );

        } catch (RestClientException error) {

            // FastAPI connection, timeout or
            // response conversion failure.

            logger.error(
                    "FastAPI request failed for scan {}: {}",
                    scanId,
                    error.toString()
            );

            logger.error(
                    "FastAPI exception details",
                    error
            );

            throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Cannot communicate with the AI engine",
                    error
            );
        }
    }
}
