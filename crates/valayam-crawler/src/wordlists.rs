pub const CRAWLER_PROBE_PATHS: &[&str] = &[
    // Spring Boot Actuator
    "actuator",
    "actuator/health",
    "actuator/env",
    "actuator/mappings",
    "actuator/beans",
    "actuator/configprops",
    // J2EE
    "WEB-INF/web.xml",
    "WEB-INF/struts-config.xml",
    "META-INF/MANIFEST.MF",
    "META-INF/maven/",
    // API & Schemas
    "swagger.json",
    "openapi.json",
    "swagger-ui.html",
    "swagger-ui/",
    "api-docs",
    "v2/api-docs",
    "v3/api-docs",
    "api/v1/swagger.json",
    // SOAP & GraphQL
    "graphql",
    "api/graphql",
    "ws?wsdl",
    "services?wsdl",
    // PostgREST
    "rpc/",
];
