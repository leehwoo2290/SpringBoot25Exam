package org.mbc.board.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.mbc.board.security.CustomUserDetailsService;
import org.mbc.board.security.handler.Custom403Handler;
import org.mbc.board.security.handler.CustomSocialLoginSuccessHandler;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Log4j2 // 로그 출력용
@Configuration  // 환경설정임을 명시
@RequiredArgsConstructor // final 필드에 대한 생성자
//@EnableGlobalMethodSecurity(prePostEnabled = true)  // 어노테이션으로 권한부여 -> 시큐리티6에서 차단!!
@EnableMethodSecurity(prePostEnabled = true) // 시큐리티 6에서는 EnableMethodSecurity 처리함.
// @PreAuthorize: 메서드가 호출되기 전에 접근을 허용할지 결정합니다.(사전검사)
// @PostAuthorize: 메서드가 호출된 후에 접근을 허용할지 결정합니다.(사후검사)
// @Secured: 특정 롤(role)로 접근을 제한합니다.
// @RolesAllowed: 특정 롤(role)로 접근을 제한합니다 (JSR-250).
// 게시물의 목록은 로그인 여부에 관계없이 볼 수 있지만 글쓰기는 권한이 있어야 가능!!!!
// 해당 컨트롤러에 적용하면 된다. -> BoardController
// registerGet() -> @PreAuthorize("hasRole('USER')") -> 게시글등록페이지로가기전에 USER권한인지 봄
// read() -> @PreAuthorize("isAuthenticated()") -> 로그인한 사용자인지 확인
// modify() -> @PreAuthorize("principal.username == #boardDTO.writer") -> 작성자인지
// remove() -> @PreAuthorize("principal.username == #boardDTO.writer") -> 작성자인지
// 표현식 https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
public class CustomSecurityConfig {
    // 스프링시큐리티 환경설정 하는 부분
    // board/list 접속시 /login 페이지로 자동 이동(시큐리티 내장된 로그인 페이지 : id (user)
    // Using generated security password: 056b482c-b7f9-4582-8a48-392bdc5e9d55(1회용)

    // p704추가 자동로그인용 데이터베이스 연동
    private final DataSource dataSource;  
    
    // p704추가 User 객체 처리용
    private final CustomUserDetailsService customUserDetailsService;

    @Bean  // Spring 레거시에는 root-context.xml에서 설정 한 부분
    public SecurityFilterChain FilterChain(HttpSecurity http) throws Exception {
        // 리턴 값                          파라미터                 예외처리
        // 강제 로그인 안하는 메서드용

        log.info("----------------CustomSecurityConfig.filterChain() 메서드 실행 ----------------------");
        log.info("--------------강제로 로그인 하지 않음--------------");
        log.info("--------------모든 사용자가 모든 경로에 접근 할 수 있음.---------");
        log.info("--------------application.properties파일에 로그 출력 레벨 추가---------");
        //logging.level.org.springframework.security.web= debug
        //logging.level.org.zerock.security = debug
        //logging.level.org.springframework.security=trace

        // 이메서드 안쪽에 커스텀한 실행문을 넣으면 동작 하게 설정

        // 실제로 인증을 처리하는 UserDetailsService 인터페이스를 사용해서 실제 인증을 커스텀함
        // UserDetailsService.loadUserByUserName() 실제 인증을 처리할 때 호출 되는 부분 (단 1개의 메서드를 가짐)
        // username이라고 부르는 사용자의 아이디를 인증 코드로 구현

        // formLogin()' is deprecated since version 6.1 and marked for removal
        // http.formLogin();  시큐리티 버전 6.1이상 급에서는 사용하지 말것!!!
        // 람다식으로 변환해서 사용 -> 시큐리티 5버전에서는 매개변수가 없는 메서드를 사용가능 -> 6버전이상에서는 deprecated
            http.formLogin(form -> {
                // 시큐리티 6버전이상에서는 람다식 으로 변환하여 사용됨.
                log.info("======= 커스텀한 로그인 페이지 호출=======");
                form.loginPage("/member/login")
                ;  // 로그인페이지 커스텀 p694
                //successForwardUrl("/board/list");

                // http://localhost/member/login.html
            });

            // http.csrf().disable()
            // 6.1 버전에서 제외 됨 (스프링 3.0이후 버전에서는 사용 안됨)
            // 람다식으로 사용할 것을 권고 함. 아래로 변경
            http.csrf(httpSecurityCsrfConfigurer -> {
                // csrf 토큰에 대한 비활성화
                // 실무에서는 사용하면 안됨
                // 프론트에 아래코드 필수
                // <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}">
                log.info("======= CSRF 비활성화 호출=======");
                httpSecurityCsrfConfigurer.disable();
            });

            // p704 자동로그인 기능 구현 추가
            http.rememberMe(httpSecurityRememberMeConfigurer -> {
                httpSecurityRememberMeConfigurer.key("12345678") // key는 개발자 맘대로(쿠키값을 인코딩시 활용)
                        .tokenRepository(persistentTokenRepository())  // 필요한 정보를 저장(하단 메서드추가)
                        .userDetailsService(customUserDetailsService)  // User 객체 이용
                        .tokenValiditySeconds(60*60*24*30); // 30일 보관
                log.info("======= 자동 로그인기법 rememberMe 호출=======");
                //                            초 분 시 일 쿠기의 maxAge()
            });

            // p746 카카오로그인 추가
            // 시큐리티 6버전 차단 !! http.oauth2Login().loginPage("/member/login");
            http.oauth2Login(httpSecurityOAuth2LoginConfigurer -> {
                httpSecurityOAuth2LoginConfigurer.loginPage("/member/login");
                httpSecurityOAuth2LoginConfigurer.successHandler(authenticationSuccessHandler()); // 761 추가 소설로그인 암호 강제 변경
            });

            // p718 403예외처리 핸들러 사용
            http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
                httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(accessDeniedHandler());
                                                                            // 하단에 메서드 추가
            });

        return http.build();
    }

    @Bean // 내장된 403를 사용하는 것이 아니라 내가 만든 재정의 핸들러를 활용한다.
    public AccessDeniedHandler accessDeniedHandler() {
        return new Custom403Handler(); // org.mbc.board.security.handler
    }

    @Bean // 자동로그인용 데이터베이스 처리
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        log.info("======= persistentTokenRepository 토큰생성기법 호출 =======");
        return jdbcTokenRepository;
        //https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/rememberme/PersistentTokenRepository.html
    }

    // p683 정적페이지에 시큐리티 제외 처리
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // /css와 같이 정적 자원들에 대한 시큐리티 적용 제외
        log.info("--- CustomSecurityConfig.WebSecurityCustomizer() 메서드 실행 ---------");
        log.info("--- toStaticResources에 ignoring처리됨 ---");
        return (web) -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        // No security for GET /css/styles.css
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // p689 패스워드를 암호화 처리하는 용도
        log.info("======= 패스워드 암화기법 처리 메서드 실행 =======");
        return new BCryptPasswordEncoder(); // 해시코드로 암호화기법을 적용
    }

    @Bean // p760 커스텀 소설로그인 성공클래스 사용
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return new CustomSocialLoginSuccessHandler(passwordEncoder());
        // 기존 내장된 것을 커스텀한 객체로 활용
    }
}
