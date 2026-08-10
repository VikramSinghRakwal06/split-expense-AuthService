package com.payflow.auth.config;

import com.payflow.auth.security.JwtAuthenticationEntryPoint;
import com.payflow.auth.security.JwtAuthenticationFilter;
import com.payflow.auth.security.RestAccessDeniedHandler;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Web security for auth-service: stateless bearer-token authentication with a small set
 * of deliberately public endpoints.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** Endpoints that must be reachable without a token, or nobody could ever get one. */
    private static final String[] PUBLIC_ENDPOINTS = {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh"
    };

    /** Health probes and the API contract, needed by orchestrators and client tooling. */
    private static final String[] INFRASTRUCTURE_ENDPOINTS = {
        "/actuator/health",
        "/actuator/health/**",
        "/swagger-ui/**",
        "/swagger-ui.html",
        "/v3/api-docs",
        "/v3/api-docs/**"
    };

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            JwtAuthenticationEntryPoint authenticationEntryPoint,
            RestAccessDeniedHandler accessDeniedHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    /**
     * The filter chain.
     *
     * <p>Order is the substance of this bean. The JWT filter runs before
     * {@code UsernamePasswordAuthenticationFilter} so that the {@code SecurityContext} is
     * already populated by the time the authorisation rules are evaluated; a filter
     * placed after it would be too late to affect the decision.
     *
     * @param http the builder Spring Security hands us
     * @return the configured chain
     * @throws Exception if the chain cannot be built
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // CSRF protection defends against a browser silently attaching ambient
                // credentials (a session cookie) to a forged cross-site request. This
                // service issues no cookies and keeps no session: the only credential is
                // a bearer token that JavaScript must read from storage and set on an
                // Authorization header, which a cross-site form post cannot do. With no
                // ambient credential to abuse, CSRF tokens would guard nothing.
                .csrf(csrf -> csrf.disable())

                // No HTTP session is ever created; the JWT carries the whole identity.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(INFRASTRUCTURE_ENDPOINTS).permitAll()
                        // Metrics and prometheus carry operational detail: not public.
                        .anyRequest().authenticated())

                // Authentication and authorisation failures happen inside the chain,
                // where @RestControllerAdvice cannot reach; these keep the error body
                // identical to every other error the service returns.
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * Stops Boot from also registering {@link JwtAuthenticationFilter} directly with the
     * servlet container.
     *
     * <p>Any {@code Filter} bean is auto-registered by servlet auto-configuration, which
     * would place this one in front of the whole application rather than at its intended
     * position inside the security chain. The chain wiring above is the only registration
     * that should exist.
     *
     * @param filter the JWT filter, wired into the chain by {@code securityFilterChain}
     * @return a registration whose sole purpose is to be disabled
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterContainerRegistration(
            JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> registration =
                new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    /**
     * BCrypt at the default strength of 10. It is adaptive and salts each hash
     * internally, so no separate salt column is needed.
     *
     * @return the encoder used for both registration and login verification
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Authentication manager backed by the database-backed {@code UserDetailsService}.
     *
     * <p>Built explicitly rather than pulled from auto-configuration so the password
     * encoder in use is visible at the point the provider is wired.
     *
     * @param userDetailsService loads accounts by email
     * @param passwordEncoder    verifies the submitted password against the stored hash
     * @return manager used by {@code AuthService} to authenticate logins
     */
    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }
}
