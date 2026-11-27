
package com.cybershield.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class GuestRateLimitService {

    private static final String SCAN_KEY = "guest:scan";
    private static final String EXPLANATION_KEY =
            "guest:explanation";

    private static final String INCREMENT_SQL = """
            INSERT INTO public.guest_rate_limits (
                quota_key,
                request_count,
                window_started_at
            )
            VALUES (?, 1, NOW())
            ON CONFLICT (quota_key)
            DO UPDATE SET
                request_count = CASE
                    WHEN guest_rate_limits.window_started_at
                         <= NOW() - INTERVAL '1 hour'
                    THEN 1
                    ELSE guest_rate_limits.request_count + 1
                END,
                window_started_at = CASE
                    WHEN guest_rate_limits.window_started_at
                         <= NOW() - INTERVAL '1 hour'
                    THEN NOW()
                    ELSE guest_rate_limits.window_started_at
                END
            WHERE
                guest_rate_limits.window_started_at
                    <= NOW() - INTERVAL '1 hour'
                OR guest_rate_limits.request_count < ?
            RETURNING request_count
            """;

    private final JdbcTemplate jdbcTemplate;
    private final int scanLimit;
    private final int explanationLimit;

    public GuestRateLimitService(
            JdbcTemplate jdbcTemplate,
            @Value("${GUEST_SCANS_PER_HOUR:60}")
            int scanLimit,
            @Value("${GUEST_EXPLANATIONS_PER_HOUR:15}")
            int explanationLimit
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.scanLimit = Math.max(1, scanLimit);
        this.explanationLimit = Math.max(1, explanationLimit);
    }

    public boolean allowScan() {
        return consume(SCAN_KEY, scanLimit);
    }

    public boolean allowExplanation() {
        return consume(EXPLANATION_KEY, explanationLimit);
    }

    private boolean consume(String key, int limit) {
        try {
            ResultSetExtractor<Boolean> extractor =
                    rs -> rs.next();

            return Boolean.TRUE.equals(
                    jdbcTemplate.query(
                            INCREMENT_SQL,
                            extractor,
                            key,
                            limit
                    )
            );

        } catch (DataAccessException exception) {
            throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Guest rate limiting temporarily unavailable"
            );
        }
    }
}
