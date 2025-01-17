package security.jpa.global.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition(
        info = @Info(
                version = "v1",
                title = "JPASecurity API Specification",
                description = "Specification for buds"
        ),
        security = {@SecurityRequirement(name = "Bearer Authentication")}
)
@SecurityScheme(
        name = "Bearer Authentication",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
@Configuration
public class SwaggerConfig {

        @Bean
        public OpenAPI OpenAPI() {
                return new OpenAPI()
                        .components(new Components()
                                .addSecuritySchemes("Bearer Authentication",
                                        new io.swagger.v3.oas.models.security.SecurityScheme()
                                                .type(io.swagger.v3.oas.models.security.SecurityScheme.Type.HTTP)
                                                .scheme("bearer")
                                                .bearerFormat("JWT")
                                )
                        )
                        .addSecurityItem(new io.swagger.v3.oas.models.security.SecurityRequirement()
                                .addList("Bearer Authentication"));
        }
}
