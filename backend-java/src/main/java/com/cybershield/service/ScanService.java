
package com.cybershield.service;

import com.cybershield.entity.Scan;
import com.cybershield.repository.ScanRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class ScanService {

    private final ScanRepository scanRepository;

    public ScanService(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    public List<Scan> getAllScans() {
        return scanRepository.findAllByOrderByCreatedAtDesc();
    }

    public Optional<Scan> getScanById(Long id) {
        return scanRepository.findById(id);
    }

    public long getTotalScans() {
        return scanRepository.count();
    }

    public Scan saveMessageScan(
            String message,
            Map<String, Object> result) {

        return saveScan("MESSAGE", message, result);
    }

    public Scan saveUrlScan(
            String url,
            Map<String, Object> result) {

        return saveScan("URL", url, result);
    }

    public Scan saveFileScan(
        String filename,
        Map<String, Object> result) {

    return saveScan("FILE", filename, result);
}

    private Scan saveScan(
            String scanType,
            String input,
            Map<String, Object> result) {

        Scan scan = new Scan();

        scan.setScanType(scanType);
        scan.setInputText(input);

        scan.setRiskLevel(
                (String) result.get("risk_level")
        );

        Object score = result.get("risk_score");

        if (score instanceof Number number) {
            scan.setRiskScore(number.doubleValue());
        }

        scan.setResultSummary(
                (String) result.get("explanation")
        );

        scan.setStatus("COMPLETED");

        return scanRepository.save(scan);
    }
}
