package org.mbc.board.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.mbc.board.security.dto.MemberSecurityDTO;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@Log4j2
@RequiredArgsConstructor
public class CustomSocialLoginSuccessHandler implements AuthenticationSuccessHandler {
    //                      implements AuthenticationSuccessHandler 시큐리티에 내장된 인터페이스
    // 카카오톡으로 로그인 성공시 해야되는 일!!!!
    // 패스워드가 1111로 되어 있기 때문에 회원수정페이지로 이동!!!
    // 암호변경하게 셋팅
    private final PasswordEncoder passwordEncoder;

    @Override // AuthenticationSuccessHandler 구현메서드 재정의
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        log.info("CustomSocialLoginSuccessHandler.onAuthenticationSuccess 메서드 실행.....");
        log.info("authentication.getPrincipal()");
        log.info(authentication.getPrincipal()); // 로그인성공한 정보 출력

        MemberSecurityDTO memberSecurityDTO = (MemberSecurityDTO) authentication.getPrincipal();

        String encodedPw = memberSecurityDTO.getMpw(); // 암호를 가져와

        if(memberSecurityDTO.isSocial() && (memberSecurityDTO.getMpw().equals("1111")
        || passwordEncoder.matches("1111",memberSecurityDTO.getMpw()))){
            // 소셜 이고 암호가1111 이거나 인코딩된암호가 1111 이면
            // 자동가입된 사용자기 때문에 암호 변경을 강제로 시킨다.

            log.info("회원 수정페이지로 이동합니다.....");
            response.sendRedirect("/member/modify"); // 컨트롤러 생성 필수 
            
            return  ;
        }else {
            response.sendRedirect("/board/list"); // 로그인 성공시 이동
        }
    }



}
