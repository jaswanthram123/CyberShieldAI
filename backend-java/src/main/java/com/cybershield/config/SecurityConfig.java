
package com.cybershield.config;

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

import java.util.List;

import java.util.ArrayList;
import org.springframework.beans.factory.annotation.Value;

import jakarta.servlet.DispatcherType;

@Configuration
public class SecurityConfig {

    // ---------------------------------------
    // Spring Security Configuration
    // ---------------------------------------

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http
            // Enable CORS for React frontend
            .cors(Customizer.withDefaults())

            // Local REST API configuration.
            // See production security note below.
            .csrf(csrf -> csrf.disable())

            // Do not create HTTP sessions
            .sessionManagement(session ->
                session.sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS
                )
            )

            // API authorization
            .authorizeHttpRequests(auth -> auth

                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()

                // Public health endpoint
                .requestMatchers(
                    HttpMethod.GET,
                    "/api/health"
                ).permitAll()

                // Protected AI explanation endpoint
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/scans/*/explanation"
                ).authenticated()

                // Protect all other API endpoints
                .requestMatchers("/api/**")
                    .authenticated()

                // Deny other requests
                .anyRequest().denyAll()
            )

            // HTTP Basic authentication
            .httpBasic(Customizer.withDefaults())

            // Disable browser login form
            .formLogin(form -> form.disable())

            // Disable logout endpoint
            .logout(logout -> logout.disable());

        return http.build();
    }

    // ---------------------------------------
    // Application User Authentication
    // ---------------------------------------

    @Bean
    public UserDetailsService userDetailsService(
            PasswordEncoder encoder) {

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

        return new InMemoryUserDetailsManager(
            developer
        );
    }

    // ---------------------------------------
    // Password Encryption
    // ---------------------------------------

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ---------------------------------------
    // CORS Configuration
    // ---------------------------------------


@Bean
public CorsConfigurationSource corsConfigurationSource(
        @Value("${FRONTEND_URL:}") String frontendUrl) {

    CorsConfiguration config = new CorsConfiguration();

    List<String> allowedOrigins = new ArrayList<>(List.of(
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174"
    ));

    // Add production frontend URL when configured
    if (frontendUrl != null && !frontendUrl.isBlank()) {
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

    source.registerCorsConfiguration("/api/**", config);

    return source;
}

}
