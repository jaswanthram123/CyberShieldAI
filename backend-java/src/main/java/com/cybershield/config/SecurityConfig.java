
package com.cybershield.config;

import jakarta.servlet.DispatcherType;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http
            .cors(Customizer.withDefaults())

            .csrf(csrf -> csrf.disable())

            .sessionManagement(session ->
                session.sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS
                )
            )

            .authorizeHttpRequests(auth -> auth

                .dispatcherTypeMatchers(
                    DispatcherType.ERROR
                ).permitAll()

                // Public health endpoint
                .requestMatchers(
                    HttpMethod.GET,
                    "/api/health"
                ).permitAll()

                // Public guest message scanning
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/guest/analyze/message"
                ).permitAll()

                // Public guest URL scanning
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/guest/analyze/url"
                ).permitAll()

                // Public guest file scanning
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/guest/analyze/file"
                ).permitAll()

                // Guest AI explanation uses a temporary
                // single-use token from a real guest scan
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/guest/explain"
                ).permitAll()

                // Saved developer scan explanations
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/scans/*/explanation"
                ).authenticated()

                // All other application APIs
                // require developer authentication
                .requestMatchers("/api/**")
                    .authenticated()

                .anyRequest().denyAll()
            )

            .httpBasic(Customizer.withDefaults())

            .formLogin(form -> form.disable())

            .logout(logout -> logout.disable());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(
            PasswordEncoder encoder
    ) {
        String password = System.getenv("APP_PASSWORD");

        if (password == null || password.isBlank()) {
            throw new IllegalStateException(
                "APP_PASSWORD environment variable is required"
            );
        }

        UserDetails developer = User.builder()
                .username("developer")
                .password(encoder.encode(password))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(developer);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${FRONTEND_URL:}") String frontendUrl
    ) {
        CorsConfiguration config =
                new CorsConfiguration();

        List<String> allowedOrigins =
                new ArrayList<>(List.of(
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "http://localhost:5174",
                    "http://127.0.0.1:5174"
                ));

        if (frontendUrl != null
                && !frontendUrl.isBlank()) {
            allowedOrigins.add(
                frontendUrl.strip().replaceAll("/+$", "")
            );
        }

        config.setAllowedOrigins(allowedOrigins);

        config.setAllowedMethods(List.of(
            "GET",
            "POST",
            "OPTIONS"
        ));

        config.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type"
        ));

        config.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
            "/api/**",
            config
        );

        return source;
    }
}
