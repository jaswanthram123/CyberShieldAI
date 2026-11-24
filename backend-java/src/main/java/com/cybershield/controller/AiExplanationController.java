
package com.cybershield.controller;

import com.cybershield.service.AiExplanationService;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/scans")
public class AiExplanationController {

    private final AiExplanationService explanationService;

    public AiExplanationController(
            AiExplanationService explanationService
    ) {
        this.explanationService = explanationService;
    }

    @PostMapping("/{scanId}/explanation")
    public Map<String, Object> generateExplanation(
            @PathVariable Long scanId
    ) {
        return explanationService.explainScan(scanId);
    }
}
