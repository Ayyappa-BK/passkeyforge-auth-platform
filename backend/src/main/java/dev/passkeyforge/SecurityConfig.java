package dev.passkeyforge;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.*;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
@Configuration
public class SecurityConfig {
 @Bean SecurityFilterChain security(HttpSecurity http,Sessions sessions,RateLimits limits,Audit audit) throws Exception {
  http.authorizeHttpRequests(a->a
    .requestMatchers("/api/me","/api/credentials/**","/api/totp/**","/api/recovery-codes","/api/audit","/api/sessions/**").hasRole("FULL")
    .requestMatchers("/api/**","/actuator/health/**","/actuator/prometheus").permitAll()
    .anyRequest().denyAll())
   .csrf(c->c.csrfTokenRepository(new org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository()))
   .securityContext(c->c.requireExplicitSave(true))
   .requestCache(c->c.disable()).formLogin(c->c.disable()).httpBasic(c->c.disable()).logout(c->c.disable())
   .exceptionHandling(e->e.authenticationEntryPoint((req,res,ex)->res.sendError(401)).accessDeniedHandler((req,res,ex)->res.sendError(403)))
   .headers(h->h.contentSecurityPolicy(c->c.policyDirectives("default-src 'none'; frame-ancestors 'none'")))
   .addFilterBefore(new OncePerRequestFilter() {
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
     res.setHeader("Cache-Control","no-store");
     if(req.getRequestURI().startsWith("/api/")) {
      try {
       limits.check("ip:"+req.getRemoteAddr(),120,60);
       if(req.getContentLengthLong()>65536) { res.sendError(413); return; }
      } catch(ApiError ex) { audit.event(null,"rate_limit","denied"); res.setHeader("Retry-After","60"); res.sendError(ex.status); return; }
     }
     try {
      UUID uid=sessions.require(req,"FULL");
      SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(uid.toString(),null,List.of(new SimpleGrantedAuthority("ROLE_FULL"))));
     } catch(ApiError ignored) { /* Anonymous or an intentionally restricted session. */ }
     chain.doFilter(req,res);
    }
   },AnonymousAuthenticationFilter.class);
  return http.build();
 }
}
