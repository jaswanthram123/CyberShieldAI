
package com.cybershield.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;

@Service
public class ScanIndicatorService {

    private final JdbcTemplate jdbcTemplate;

    public ScanIndicatorService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // Save one indicator
    @Transactional
    public void saveIndicator(
            Long scanId,
            String indicatorType,
            String description
    ) {
        if (scanId == null) {
            throw new IllegalArgumentException(
                    "Scan ID cannot be null"
            );
        }

        if (indicatorType == null ||
                indicatorType.isBlank() ||
                indicatorType.length() > 50) {
            throw new IllegalArgumentException(
                    "Invalid indicator type"
            );
        }

        if (description == null ||
                description.isBlank()) {
            throw new IllegalArgumentException(
                    "Invalid indicator description"
            );
        }

        String sql = """
            INSERT INTO public.scan_indicators
                (scan_id, indicator_type, description)
            VALUES (?, ?, ?)
            """;

        jdbcTemplate.update(
                sql,
                scanId,
                indicatorType.trim(),
                description.trim().substring(
                        0,
                        Math.min(
                                description.trim().length(),
                                200
                        )
                )
        );
    }

    // Save multiple indicators for a new scan
    @Transactional
    public void saveIndicators(
            Long scanId,
            String indicatorType,
            List<String> indicators
    ) {
        if (indicators == null || indicators.isEmpty()) {
            return;
        }

        List<String> uniqueIndicators = indicators.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .distinct()
                .limit(10)
                .toList();

        for (String indicator : uniqueIndicators) {
            saveIndicator(
                    scanId,
                    indicatorType,
                    indicator
            );
        }
    }

    // Retrieve findings for AI explanations
    @Transactional(readOnly = true)
    public List<String> getIndicators(Long scanId) {

        String sql = """
            SELECT indicator_type, description
            FROM public.scan_indicators
            WHERE scan_id = ?
            ORDER BY id
            LIMIT 10
            """;

        return jdbcTemplate.query(
                sql,
                (rs, rowNum) ->
                        rs.getString("indicator_type")
                        + ": "
                        + rs.getString("description"),
                scanId
        );
    }
}
