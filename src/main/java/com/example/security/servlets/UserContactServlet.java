package com.example.security.servlets;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;

/**
 * [예제 서블릿] 심플 DSL 기반 다중 파라미터 보안 검증 샘플 서블릿 (경량 버전)
 * - 경로: /aemapi/user/contact
 * - 메서드: POST
 * - 보안 정책:
 *   1. 허용 HTTP Method: POST
 *   2. 허용 Referer: 기본 도메인(abc.com) 및 partner.abc.com
 *   3. 심플 DSL을 통한 초간단 파라미터 제약조건 선언 (JSON 이스케이프 불필요!)
 *   4. defaultPolicy로부터 전사 공통 파라미터(page, lang 등) 자동 상속
 */
@Component(
        service = { Servlet.class },
        property = {
                "sling.servlet.paths=/aemapi/user/contact",
                "sling.servlet.methods=POST",
                "service.description=User Contact Inquiry Servlet",

                // 1. 허용 메서드 및 Referer 설정
                "security.methods=POST",
                "security.allowedReferrers=partner.abc.com",

                // 2. 심플 DSL 파라미터 규칙 (JSON 이스케이프 없이 직관적으로 선언)
                "security.params=name:required:2..20:korean",               // 이름: 필수, 2~20자, 한글/영문
                "security.params=email:required:email:50",                  // 이메일: 필수, 이메일 형식, 최대 50자
                "security.params=phone:required:phone",                     // 전화번호: 필수, 휴대폰 정규식
                "security.params=inquiryType:required:tech|billing|general",// 문의타입: 필수, tech/billing/general 중 1개
                "security.params=zipCode:digits:5"                          // 우편번호: 선택, 숫자만, 최대 5자리
        }
)
public class UserContactServlet extends SlingAllMethodsServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(final SlingHttpServletRequest request, final SlingHttpServletResponse response)
            throws ServletException, IOException {

        // 필터에서 name, email, phone, inquiryType, zipCode 및 공통 파라미터(page 등)에 대해
        // 필수값, 길이, 정규식, Path Traversal 검증이 100% 완료된 안전한 파라미터만 서블릿에 도달합니다.
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String phone = request.getParameter("phone");
        String inquiryType = request.getParameter("inquiryType");
        String zipCode = request.getParameter("zipCode");

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(String.format(
                "{\"status\":\"success\",\"message\":\"문의가 안전하게 접수되었습니다.\",\"data\":{\"name\":\"%s\",\"email\":\"%s\",\"phone\":\"%s\",\"inquiryType\":\"%s\",\"zipCode\":\"%s\"}}",
                name, email, phone, inquiryType, zipCode != null ? zipCode : ""
        ));
    }
}
