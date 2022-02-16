package com.devjaewoo.springbootjwttutorial.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

//토큰 필터링 및 SecurityContext에 저장
public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    // 실제 필터링 로직, JWT Token의 인증정보를 현재 실행중인 SecurityContext에 저장
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String jwt = resolveToken(httpServletRequest); //request에서 Token 추출
        String requestURI = httpServletRequest.getRequestURI(); //request된 URI 추출

        //Token 검증 (공백이 아니고 유효한 토큰인 경우)
        if(StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            //의존성 주입받은 tokenProvider에 Token 집어넣고 Authentication 받아오기
            Authentication authentication = tokenProvider.getAuthentication(jwt);

            //Security Context에 인증 정보 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다. URI: {}", authentication.getName(), requestURI);
        }
        else {
            logger.debug("유효한 JWT 토큰이 없습니다. URI: {}", requestURI);
        }

        //필터링 계속하기
        chain.doFilter(request, response);
    }

    // Request Header에서 토큰 정보를 꺼내옴
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
