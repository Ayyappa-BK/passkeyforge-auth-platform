package dev.passkeyforge;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.*;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class SecurityConfig {
  static class BoundedRequest extends HttpServletRequestWrapper {
    final byte[] body;

    BoundedRequest(HttpServletRequest req, byte[] body) {
      super(req);
      this.body = body;
    }

    @Override
    public ServletInputStream getInputStream() {
      var input = new ByteArrayInputStream(body);
      return new ServletInputStream() {
        @Override
        public int read() {
          return input.read();
        }

        @Override
        public int read(byte[] b, int off, int len) {
          return input.read(b, off, len);
        }

        @Override
        public boolean isFinished() {
          return input.available() == 0;
        }

        @Override
        public boolean isReady() {
          return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
          throw new UnsupportedOperationException("Synchronous JSON API");
        }
      };
    }

    @Override
    public BufferedReader getReader() {
      return new BufferedReader(
          new InputStreamReader(getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
    }
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http, Sessions sessions, RateLimits limits, Audit audit)
      throws Exception {
    http.authorizeHttpRequests(
            a ->
                a.dispatcherTypeMatchers(DispatcherType.ERROR)
                    .permitAll()
                    .requestMatchers(
                        "/api/me",
                        "/api/credentials/**",
                        "/api/totp/**",
                        "/api/recovery-codes",
                        "/api/audit",
                        "/api/sessions/**")
                    .hasRole("FULL")
                    .requestMatchers("/api/**", "/actuator/health/**", "/actuator/prometheus")
                    .permitAll()
                    .anyRequest()
                    .denyAll())
        .csrf(
            c ->
                c.csrfTokenRepository(
                    new org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository()))
        .securityContext(c -> c.requireExplicitSave(true))
        .requestCache(c -> c.disable())
        .formLogin(c -> c.disable())
        .httpBasic(c -> c.disable())
        .logout(c -> c.disable())
        .exceptionHandling(
            e ->
                e.authenticationEntryPoint((req, res, ex) -> res.sendError(401))
                    .accessDeniedHandler((req, res, ex) -> res.sendError(403)))
        .headers(
            h ->
                h.contentSecurityPolicy(
                    c -> c.policyDirectives("default-src 'none'; frame-ancestors 'none'")))
        .addFilterBefore(
            new OncePerRequestFilter() {
              @Override
              protected void doFilterInternal(
                  HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                  throws ServletException, IOException {
                res.setHeader("Cache-Control", "no-store");
                if (req.getRequestURI().startsWith("/api/")) {
                  try {
                    limits.check("ip:" + req.getRemoteAddr(), 120, 60);
                    if (req.getContentLengthLong() > 65536) {
                      res.sendError(413);
                      return;
                    }
                  } catch (ApiError ex) {
                    res.setHeader("Retry-After", "60");
                    res.sendError(ex.status);
                    return;
                  }
                }
                try {
                  UUID uid = sessions.require(req, "FULL");
                  SecurityContextHolder.getContext()
                      .setAuthentication(
                          new UsernamePasswordAuthenticationToken(
                              uid.toString(),
                              null,
                              List.of(new SimpleGrantedAuthority("ROLE_FULL"))));
                } catch (ApiError ignored) {
                  /* Anonymous or an intentionally restricted session. */
                }
                if (req.getRequestURI().startsWith("/api/")
                    && !Set.of("GET", "HEAD", "OPTIONS").contains(req.getMethod())) {
                  byte[] body = req.getInputStream().readNBytes(65537);
                  if (body.length > 65536) {
                    res.sendError(413);
                    return;
                  }
                  chain.doFilter(new BoundedRequest(req, body), res);
                } else chain.doFilter(req, res);
              }
            },
            AnonymousAuthenticationFilter.class);
    return http.build();
  }
}
