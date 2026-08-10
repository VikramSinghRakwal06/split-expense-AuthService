package com.payflow.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Turns a {@code Authorization: Bearer <jwt>} header into an authenticated
 * {@code SecurityContext} for the duration of one request.
 *
 * <h2>Where this sits in the chain</h2>
 *
 * <p>Registered <em>before</em> {@code UsernamePasswordAuthenticationFilter}. That
 * position matters: the username/password filter is the point at which Spring Security
 * would otherwise try to authenticate a request itself, and by the time the chain reaches
 * the authorisation checks the {@code SecurityContext} has to be populated already.
 * Running first means a valid bearer token is established as the current authentication
 * before anything downstream asks "is this caller allowed?".
 *
 * <h2>What it deliberately does not do</h2>
 *
 * <p>A missing, malformed, expired or otherwise unusable token is <strong>not</strong> an
 * error here — the filter simply leaves the context empty and calls the rest of the
 * chain. Rejecting the request is the job of the authorisation rules in
 * {@code SecurityConfig}, which is what allows the same filter to sit in front of public
 * endpoints like {@code /login} without having to special-case them. The caller sees a
 * 401 from {@link JwtAuthenticationEntryPoint} only if the endpoint actually required
 * authentication.
 *
 * <p>Extending {@code OncePerRequestFilter} guarantees the work happens a single time per
 * request even when a forward or error dispatch re-enters the chain, which otherwise
 * causes the token to be parsed several times per call.
 *
 * @see JwtService for why access and refresh tokens are separate
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractBearerToken(request);

        if (token == null || SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String email = jwtService.extractUsername(token);
            if (email != null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
                if (jwtService.isTokenValid(token, userDetails)) {
                    authenticate(request, userDetails);
                }
            }
        } catch (Exception ex) {
            // Covers bad signatures, expired tokens and accounts deleted since issue.
            // Logged at debug because unauthenticated traffic is routine and an
            // attacker should not be able to fill the logs by sending junk tokens.
            log.debug("Bearer token rejected: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Places the verified identity in the context, with no credentials attached — the
     * token has already been checked and the password hash must never be held here.
     */
    private void authenticate(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * @return the raw JWT, or null when the header is absent or not a bearer credential
     */
    private String extractBearerToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
