package com.splitexpense.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI description of the service, including the bearer scheme so the Swagger UI can
 * call the protected endpoints with a token obtained from {@code /login}.
 */
@Configuration
public class OpenApiConfig {

    private static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI authServiceOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("SplitExpense Auth Service")
                        .version("v1")
                        .description("""
                                Accounts, authentication and JWT issuance for the SplitExpense \
                                wallet platform. Access tokens are verified independently \
                                by every other SplitExpense service; refresh tokens are \
                                validated against this service's database so that logout \
                                takes effect immediately.""")
                        .contact(new Contact().name("SplitExpense Platform"))
                        .license(new License().name("Proprietary")))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME,
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Access token returned by /api/v1/auth/login")))
                // Applied globally; the public endpoints simply ignore it.
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME));
    }
}
