
package com.cybershield.config;

import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.boot.webmvc.error.DefaultErrorAttributes;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.web.context.request.WebRequest;

@Component
public class SafeErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(
            WebRequest webRequest,
            ErrorAttributeOptions options) {

        ErrorAttributeOptions safeOptions =
                options.excluding(
                    ErrorAttributeOptions.Include.STACK_TRACE,
                    ErrorAttributeOptions.Include.EXCEPTION,
                    ErrorAttributeOptions.Include.BINDING_ERRORS,
                    ErrorAttributeOptions.Include.MESSAGE
                );

        Map<String, Object> attributes =
                super.getErrorAttributes(
                    webRequest,
                    safeOptions
                );

        attributes.remove("trace");
        attributes.remove("exception");
        attributes.remove("errors");
        attributes.remove("message");

        return attributes;
    }
}
