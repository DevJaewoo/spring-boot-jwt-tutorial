package com.devjaewoo.springbootjwttutorial.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

//Token 생성, 유효성 검증
@Component
public class TokenProvider implements InitializingBean {

    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds;

    private Key key;

    // @Value를 통해 application.yml에서 설정한 값이 넘어온다.
    public TokenProvider(@Value("${jwt.secret}") String secret, @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    @Override
    public void afterPropertiesSet() throws Exception { //생성자로 secret 값과 만료시간을 의존성 주입 받은 후에 key 변수에 할당하기 위해서 InitializingBean implement
        byte[] keyBytes = Decoders.BASE64.decode(secret); //Decode
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    //Authentication으로 Token 반환
    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream() //어딘가에서 권한들 받아오기
                .map(GrantedAuthority::getAuthority) //권한 문자열로 가져옴
                .collect(Collectors.joining(",")); //콤마(,)로 연결해서 하나의 문자열로 만든다. 나중에 Payload에 들어간다.
        // Authentication a = new [Ctrl + Tab]

        long now = new Date().getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds); //Token이 만료되는 시간

        return Jwts.builder()
                .setSubject(authentication.getName()) //Token 이름
                .claim(AUTHORITIES_KEY, authorities) //claim: Token에 담을 각 정보. 여기선 모든 권한들을 String 하나로 압축해서 claim 하나만 넣는듯
                .signWith(key, SignatureAlgorithm.HS512) //키, 암호화 알고리즘
                .setExpiration(validity) //만료시간
                .compact(); //Token 생성
    }

    //Token으로 Authentication 반환
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key) //서명 검증
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities = //권한 정보 빼내기
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities); //권한 정보로 User 객체 만들음

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    //Token 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("JWT 토큰이 잘못되었습니다.");
        }

        return false;
    }
}
