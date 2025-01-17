package security.jpa.global.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import security.jpa.global.common.exception.CommonException;
import security.jpa.global.common.exception.ErrorCode;
import security.jpa.global.security.constants.ApplicationConstants;
import security.jpa.global.security.service.MemberDetails;
import security.jpa.global.security.service.MemberDetailsService;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@RequiredArgsConstructor
public class JWTTokenValidatorFilter extends OncePerRequestFilter {

    private final MemberDetailsService memberDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            String token = authorizationHeader.substring(7);
            try {
                SecretKey secretKey = Keys.hmacShaKeyFor(ApplicationConstants.getJwtSecretKey().getBytes(StandardCharsets.UTF_8));

                Claims claims = Jwts.parserBuilder()
                                                    .setSigningKey(secretKey)
                                                    .build()
                                                    .parseClaimsJws(token)
                                                    .getBody();

                // 사용자 정보 추출
                String username = claims.get("username", String.class);
                String authorities = claims.get("authorities", String.class);

                // UserDetailsService를 통해 사용자 정보 로드
                MemberDetails memberDetails = memberDetailsService.loadUserByUsername(username);

                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        memberDetails, null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));

                // SecurityContextHolder에 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (Exception e) {
                throw new CommonException(ErrorCode.INVALID_TOKEN_ERROR);
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        return path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/swagger-resources") ||
                path.equals("/auth/signin") ||
                path.equals("/auth/signup");
    }
}
