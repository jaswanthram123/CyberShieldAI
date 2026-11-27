
package com.cybershield.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Map;

@Service
public class AiEngineService {

    private final RestClient restClient;

    public AiEngineService(
            @Value("${ai.engine.url}") String aiEngineUrl,
            @Value("${AI_ENGINE_INTERNAL_KEY}") String internalKey
    ) {

        if (internalKey == null || internalKey.isBlank()) {
            throw new IllegalStateException(
                    "AI_ENGINE_INTERNAL_KEY is required"
            );
        }

        SimpleClientHttpRequestFactory factory =
                new SimpleClientHttpRequestFactory();

        factory.setConnectTimeout(Duration.ofSeconds(5));
        factory.setReadTimeout(Duration.ofSeconds(30));

        this.restClient = RestClient.builder()
                .baseUrl(aiEngineUrl)
                .defaultHeader(
                        "X-Internal-API-Key",
                        internalKey
                )
                .requestFactory(factory)
                .build();
    }

    public Map<String, Object> analyzeMessage(String message) {

        return restClient.post()
                .uri("/analyze/message")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("message", message))
                .retrieve()
                .body(new ParameterizedTypeReference<
                        Map<String, Object>>() {});
    }

    public Map<String, Object> analyzeUrl(String url) {

        return restClient.post()
                .uri("/analyze/url")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("url", url))
                .retrieve()
                .body(new ParameterizedTypeReference<
                        Map<String, Object>>() {});
    }

    public Map<String, Object> analyzeFile(
            String filename,
            byte[] fileBytes
    ) {

        ByteArrayResource resource =
                new ByteArrayResource(fileBytes) {

                    @Override
                    public String getFilename() {
                        return filename;
                    }
                };

        HttpHeaders fileHeaders = new HttpHeaders();
        fileHeaders.setContentType(
                MediaType.APPLICATION_OCTET_STREAM
        );

        HttpEntity<ByteArrayResource> filePart =
                new HttpEntity<>(resource, fileHeaders);

        MultiValueMap<String, Object> body =
                new LinkedMultiValueMap<>();

        body.add("file", filePart);

        return restClient.post()
                .uri("/analyze/file")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(body)
                .retrieve()
                .body(new ParameterizedTypeReference<
                        Map<String, Object>>() {});
    }
}
