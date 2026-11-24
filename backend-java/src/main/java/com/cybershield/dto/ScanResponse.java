
package com.cybershield.dto;

import com.cybershield.entity.Scan;
import java.time.OffsetDateTime;

public record ScanResponse(
        Long id,
        String scanType,
        String riskLevel,
        Double riskScore,
        String resultSummary,
        String status,
        OffsetDateTime createdAt
) {
    public static ScanResponse from(Scan scan) {
        return new ScanResponse(
                scan.getId(),
                scan.getScanType(),
                scan.getRiskLevel(),
                scan.getRiskScore(),
                scan.getResultSummary(),
                scan.getStatus(),
                scan.getCreatedAt()
        );
    }
}
