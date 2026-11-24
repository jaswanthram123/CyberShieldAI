
package com.cybershield.controller;

import com.cybershield.dto.ScanResponse;
import com.cybershield.service.ScanService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scans")
@CrossOrigin(origins = "http://localhost:5173")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @GetMapping
    public List<ScanResponse> getAllScans() {
        return scanService.getAllScans()
                .stream()
                .map(ScanResponse::from)
                .toList();
    }

    @GetMapping("/count")
    public Map<String, Long> getTotalScans() {
        return Map.of(
                "totalScans",
                scanService.getTotalScans()
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScanResponse> getScanById(
            @PathVariable Long id) {

        return scanService.getScanById(id)
                .map(ScanResponse::from)
                .map(ResponseEntity::ok)
                .orElseGet(() ->
                        ResponseEntity.notFound().build()
                );
    }
}
