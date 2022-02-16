package com.devjaewoo.springbootjwttutorial.config;

import com.devjaewoo.springbootjwttutorial.jwt.JwtAccessDeniedHandler;
import com.devjaewoo.springbootjwttutorial.jwt.JwtAuthenticationEntryPoint;
import com.devjaewoo.springbootjwttutorial.jwt.JwtSecurityConfig;
import com.devjaewoo.springbootjwttutorial.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //@PreAuthorize를 메소드 단위로 추가하기 위해 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Autowired
    public SecurityConfig(TokenProvider tokenProvider, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint, JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/h2-console/**", "/favicon.ico"); //h2-console과 아이콘은 보안 무시
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests() //HTTP Servlet Request 사용하는 요청에 대한 접근 제한 설정
//                .antMatchers("/api/hello").permitAll() //api/hello에 대한 접근은 허용
//                .anyRequest().authenticated(); //그러나 나머지 요청들은 모두 인증받아야만 함
        http
                //Token을 사용하기 때문에 CSRF는 Disable 한다고 함
                .csrf().disable()

                //Exception을 Handling 해야될 때 우리가 만든 클레스로 핸들링
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //h2 콘솔을 위한 설정이라고 함
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                //세션을 사용하지 않기 때문에 Stateless로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                //Token을 받기 위한 API와 회원가입을 위한 API는 Token이 없는 상태에서 요쳥이 오기 때문에 허용, 나머지는 인증 필요
                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                //JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 적용
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }


}
