package com.example.security.servlets;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;

/**
 * [예제 서블릿] 문의 접수 샘플 서블릿
 * - 경로: /aemapi/user/contact
 * - 메서드: POST
 * - 보안 정책은 서블릿 코드와 분리되어 config/com.example.security.registry.EndpointPolicyConfig~core-member.cfg.json 에서 관리됩니다.
 */
@Component(
        service = { Servlet.class },
        property = {
                "sling.servlet.paths=/aemapi/user/contact",
                "sling.servlet.methods=POST",
                "service.description=User Contact Inquiry Servlet"
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
