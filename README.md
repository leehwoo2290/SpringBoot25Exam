# bootShop-3.2.4
Spring boot Shping mall

1.변경사항
스프링부트3(2024-04-19)

스프링부트 3.2.4 버전으로 업데이트

스프링부트3 버전부터는 자바 17버전 이상을 사용해야합니다.

교재는 maven 이지만 gradle로 설정 함

javax에서 jakarta로 변경됨에 따라서 많은 import 들이 jakarta로 수정되었습니다.
javax.validation => jakarta.validation
javax.persistence => jakarta.persistence

CustomAuthenticationEntryPoint.java (javax.servlet => jakarta.servlet)

Security 버전이 수정됨에 따라 기존 메소드가 deprecated 됐습니다. 시큐리트 6.1 로 설정 완료

layout1.html 파일 내용 수정

thymeleaf layout 버전 증가에 따른 코드 수정

th:replace="fragments/header::header"> => th:replace="~{fragments/header::header}">

th:replace="fragments/footer::footer"> => th:replace="~{fragments/footer::footer}">
