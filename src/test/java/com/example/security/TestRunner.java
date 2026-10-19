package com.example.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

public class TestRunner {

    public static void main(String[] args) {
        List<String> testClassNames = Arrays.asList(
                "com.example.security.validators.SqlAndXssValidationTest",
                "com.example.security.validators.PathTraversalValidationTest"
        );

        List<Class<?>> testClasses = new java.util.ArrayList<>();
        for (String name : testClassNames) {
            try {
                testClasses.add(Class.forName(name));
            } catch (ClassNotFoundException e) {
                System.err.println("Test class not found: " + name);
            }
        }

        int totalPassed = 0;
        int totalFailed = 0;

        System.out.println("==================================================================");
        System.out.println("   🚀 AEM Security Filter Simple (Referer, Method, Param) 단위 테스트");
        System.out.println("==================================================================");

        for (Class<?> clazz : testClasses) {
            System.out.println("\n📦 [테스트 스위트]: " + clazz.getSimpleName());
            int suitePassed = 0;
            int suiteFailed = 0;

            for (Method method : clazz.getDeclaredMethods()) {
                if (method.isAnnotationPresent(Test.class)) {
                    DisplayName displayName = method.getAnnotation(DisplayName.class);
                    String testName = displayName != null ? displayName.value() : method.getName();

                    try {
                        java.lang.reflect.Constructor<?> ctor = clazz.getDeclaredConstructor();
                        ctor.setAccessible(true);
                        Object instance = ctor.newInstance();

                        AutoCloseable mocks = MockitoAnnotations.openMocks(instance);

                        for (Method m : clazz.getDeclaredMethods()) {
                            if (m.isAnnotationPresent(BeforeEach.class)) {
                                m.setAccessible(true);
                                m.invoke(instance);
                            }
                        }

                        method.setAccessible(true);
                        method.invoke(instance);

                        if (mocks != null) {
                            mocks.close();
                        }

                        System.out.println("   ✅ PASS: " + testName);
                        suitePassed++;
                        totalPassed++;
                    } catch (Throwable t) {
                        Throwable cause = t.getCause() != null ? t.getCause() : t;
                        System.err.println("   ❌ FAIL: " + testName + " -> " + cause.getMessage());
                        cause.printStackTrace(System.err);
                        suiteFailed++;
                        totalFailed++;
                    }
                }
            }
            System.out.println("   결과: " + suitePassed + " 통과, " + suiteFailed + " 실패");
        }

        System.out.println("\n==================================================================");
        System.out.println("   🎉 전체 테스트 요약: 총 " + (totalPassed + totalFailed) + "개 중 "
                + totalPassed + "개 성공, " + totalFailed + "개 실패");
        System.out.println("==================================================================");

        if (totalFailed > 0) {
            System.exit(1);
        }
    }
}
