
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

    public AiExplanationService(
            ScanRepository scanRepository,
            ScanIndicatorService scanIndicatorService,
            @Value("${ai.engine.url:http://127.0.0.1:8000}")
            String aiEngineUrl,
            @Value("${AI_ENGINE_INTERNAL_KEY}")
            String internalKey
    ) {
        this.scanRepository = scanRepository;
        this.scanIndicatorService = scanIndicatorService;

        if (internalKey == null || internalKey.isBlank()) {
            throw new IllegalStateException(
                    "AI_ENGINE_INTERNAL_KEY is required"
            );
        }

        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        JdkClientHttpRequestFactory factory =
                new JdkClientHttpRequestFactory(httpClient);

        factory.setReadTimeout(Duration.ofSeconds(190));

        this.restClient = RestClient.builder()
                .baseUrl(aiEngineUrl)
                .defaultHeader(
                        "X-Internal-API-Key",
                        internalKey
                )
                .requestFactory(factory)
                .build();

        logger.info(
                "AI Explanation Service configured for {}",
                aiEngineUrl
        );
    }

    private boolean validScanType(String scanType) {
        return "MESSAGE".equals(scanType)
                || "URL".equals(scanType)
                || "FILE".equals(scanType);
    }

    private boolean validRiskLevel(String riskLevel) {
        return "LOW".equals(riskLevel)
                || "MEDIUM".equals(riskLevel)
                || "HIGH".equals(riskLevel);
    }

    private void validateAnalysis(
            String scanType,
            String riskLevel,
            Number riskScore
    ) {
        if (!validScanType(scanType)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported scan type"
            );
        }

        if (!validRiskLevel(riskLevel)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid risk level"
            );
        }

        if (riskScore == null
                || !Double.isFinite(
                        riskScore.doubleValue()
                )
                || riskScore.doubleValue() < 0
                || riskScore.doubleValue() > 100) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid risk score"
            );
        }
    }

    private Map<String, Object> callAiEngine(
            String scanType,
            String riskLevel,
            Number riskScore,
            String prediction,
            List<String> indicators
    ) {
        validateAnalysis(
                scanType,
                riskLevel,
                riskScore
        );

        List<String> safeIndicators =
                indicators == null
                        ? List.of()
                        : List.copyOf(indicators);

        Map<String, Object> request =
                new LinkedHashMap<>();

        request.put("scan_type", scanType);
        request.put("risk_level", riskLevel);
        request.put("risk_score", riskScore);
        request.put(
                "prediction",
                prediction == null
                        ? "UNKNOWN"
                        : prediction
        );
        request.put("indicators", safeIndicators);

        try {
            Map<?, ?> aiResponse = restClient.post()
                    .uri("/explain")
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(Map.class);

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
                    || !(explanation instanceof String text)
                    || text.isBlank()) {

                logger.error(
                        "AI engine returned an incomplete explanation"
                );

                throw new ResponseStatusException(
                        HttpStatus.BAD_GATEWAY,
                        "AI explanation was not completed"
                );
            }

            Map<String, Object> response =
                    new LinkedHashMap<>();

            response.put("scan_type", scanType);
            response.put("risk_level", riskLevel);
            response.put("risk_score", riskScore);
            response.put("status", status);
            response.put(
                    "model",
                    aiResponse.get("model")
            );
            response.put("explanation", explanation);
            response.put(
                    "disclaimer",
                    aiResponse.get("disclaimer")
            );
            response.put("indicators", safeIndicators);

            return response;

        } catch (RestClientResponseException error) {
            logger.error(
                    "FastAPI explanation request returned HTTP {}",
                    error.getStatusCode().value()
            );

            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    "AI engine rejected the explanation request",
                    error
            );

        } catch (RestClientException error) {
            logger.error(
                    "Cannot communicate with AI explanation engine",
                    error
            );

            throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Cannot communicate with the AI engine",
                    error
            );
        }
    }

    // =========================================
    // DEVELOPER: Explain a stored Supabase scan
    // =========================================

    public Map<String, Object> explainScan(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND,
                                "Scan not found"
                        )
                );

        String scanType = scan.getScanType();
        String riskLevel = scan.getRiskLevel();

        if (scan.getRiskScore() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Risk score is missing"
            );
        }

        validateAnalysis(
                scanType,
                riskLevel,
                scan.getRiskScore()
        );

        List<String> indicators =
                scanIndicatorService.getIndicators(scanId);

        logger.info(
                "Generating AI explanation for saved scan {}",
                scanId
        );

        Map<String, Object> response =
                callAiEngine(
                        scanType,
                        riskLevel,
                        scan.getRiskScore(),
                        "UNKNOWN",
                        indicators
                );

        response.put("scan_id", scan.getId());

        logger.info(
                "Saved scan {} explanation completed",
                scanId
        );

        return response;
    }

    // =========================================
    // GUEST: Explain an unsaved scan result
    // =========================================

    public Map<String, Object> explainGuestAnalysis(
            String scanType,
            String riskLevel,
            Number riskScore,
            String prediction,
            List<String> indicators
    ) {
        logger.info(
                "Generating guest AI explanation for scan type {}",
                scanType
        );

        Map<String, Object> response =
                callAiEngine(
                        scanType,
                        riskLevel,
                        riskScore,
                        prediction,
                        indicators
                );

        response.put("guest_mode", true);
        response.put("saved", false);

        logger.info(
                "Guest AI explanation completed"
        );

        return response;
    }
}
