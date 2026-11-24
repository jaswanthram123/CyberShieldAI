
package com.cybershield.controller;

import com.cybershield.entity.Scan;
import com.cybershield.service.ScanService;

import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/threat-intelligence")
public class ThreatIntelligenceController {

    private final ScanService scanService;

    public ThreatIntelligenceController(
            ScanService scanService) {
        this.scanService = scanService;
    }

    @GetMapping("/summary")
    public Map<String, Object> getSummary() {

        List<Scan> scans = scanService.getAllScans();

        long totalScans = scans.size();

        long highRisk = scans.stream()
                .filter(scan ->
                        "HIGH".equalsIgnoreCase(
                                scan.getRiskLevel()))
                .count();

        long mediumRisk = scans.stream()
                .filter(scan ->
                        "MEDIUM".equalsIgnoreCase(
                                scan.getRiskLevel()))
                .count();

        long lowRisk = scans.stream()
                .filter(scan ->
                        "LOW".equalsIgnoreCase(
                                scan.getRiskLevel()))
                .count();

        long messageScans = scans.stream()
                .filter(scan ->
                        "MESSAGE".equalsIgnoreCase(
                                scan.getScanType()))
                .count();

        long urlScans = scans.stream()
                .filter(scan ->
                        "URL".equalsIgnoreCase(
                                scan.getScanType()))
                .count();

        long fileScans = scans.stream()
                .filter(scan ->
                        "FILE".equalsIgnoreCase(
                                scan.getScanType()))
                .count();

        List<Map<String, Object>> recentHighRisk =
                scans.stream()
                        .filter(scan ->
                                "HIGH".equalsIgnoreCase(
                                        scan.getRiskLevel()))
                        .limit(5)
                        .map(scan -> {
                            Map<String, Object> item =
                                    new LinkedHashMap<>();

                            item.put("id", scan.getId());
                            item.put("scanType", scan.getScanType());
                            item.put("riskLevel", scan.getRiskLevel());
                            item.put("riskScore", scan.getRiskScore());
                            item.put("resultSummary",
                                    scan.getResultSummary());
                            item.put("createdAt", scan.getCreatedAt());

                            return item;
                        })
                        .collect(Collectors.toList());

        Map<String, Object> response =
                new LinkedHashMap<>();

        response.put("totalScans", totalScans);
        response.put("highRisk", highRisk);
        response.put("mediumRisk", mediumRisk);
        response.put("lowRisk", lowRisk);

        response.put("messageScans", messageScans);
        response.put("urlScans", urlScans);
        response.put("fileScans", fileScans);

        response.put("recentHighRisk", recentHighRisk);

        return response;
    }
}
