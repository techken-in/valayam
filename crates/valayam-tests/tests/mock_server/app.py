from fastapi import FastAPI
import uvicorn

# Import all nested routers
from routers.misconfiguration.cors.endpoints import router as cors_router
from routers.logic.graphql.endpoints import router as graphql_router
from routers.auth.endpoints import router as oauth_router
from routers.injection.sqli.endpoints import router as sqli_router
from routers.injection.xss.endpoints import router as xss_router
from routers.file_ops.lfi.endpoints import router as lfi_router
from routers.request_forgery.ssrf.endpoints import router as ssrf_router
from routers.injection.osci.endpoints import router as osci_router
from routers.access_control.idor.endpoints import router as idor_router
from routers.auth.jwt.endpoints import router as jwt_router
from routers.client_side.open_redirect.endpoints import router as open_redirect_router
from routers.injection.xxe.endpoints import router as xxe_router
from routers.logic.hpp.endpoints import router as hpp_router
from routers.access_control.bac.endpoints import router as bac_router
from routers.injection.ssti.endpoints import router as ssti_router
from routers.injection.ssti_client.endpoints import router as ssti_client_router
from routers.deserialization.endpoints import router as deserialization_router
from routers.request_forgery.csrf.endpoints import router as csrf_router
from routers.access_control.mass_assignment.endpoints import router as mass_assignment_router
from routers.auth.auth_bypass.endpoints import router as auth_bypass_router
from routers.data_exposure.debug.endpoints import router as debug_router
from routers.data_exposure.crypto.endpoints import router as crypto_router
from routers.data_exposure.crypto_padding.endpoints import router as crypto_padding_router
from routers.misconfiguration.host_header.endpoints import router as host_header_router
from routers.file_ops.file_upload.endpoints import router as file_upload_router
from routers.logic.rate_limiting.endpoints import router as rate_limiting_router
from routers.injection.xpath.endpoints import router as xpath_router
from routers.injection.ldap.endpoints import router as ldap_router
from routers.injection.nosqli.endpoints import router as nosqli_router
from routers.injection.crlf.endpoints import router as crlf_router
from routers.deserialization.yaml_deserialization.endpoints import router as yaml_deserialization_router
from routers.file_ops.zip_slip.endpoints import router as zip_slip_router
from routers.auth.jwt_weak.endpoints import router as jwt_weak_router
from routers.access_control.bfla.endpoints import router as bfla_router
from routers.misconfiguration.clickjacking.endpoints import router as clickjacking_router
from routers.request_forgery.ssrf_blind.endpoints import router as ssrf_blind_router
from routers.client_side.xss_dom.endpoints import router as xss_dom_router
from routers.injection.csv_injection.endpoints import router as csv_injection_router
from routers.logic.graphql_dos.endpoints import router as graphql_dos_router
from routers.client_side.open_redirect_dom.endpoints import router as open_redirect_dom_router
from routers.auth.jwt_kid.endpoints import router as jwt_kid_router
from routers.auth.session_fixation.endpoints import router as session_fixation_router
from routers.auth.oauth_implicit.endpoints import router as oauth_implicit_router
from routers.logic.race_condition.endpoints import router as race_condition_router
from routers.http_smuggling.endpoints import router as http_smuggling_router
from routers.xst.endpoints import router as xst_router
from routers.injection.xxe_dos.endpoints import router as xxe_dos_router
from routers.injection.xxe_oob.endpoints import router as xxe_oob_router
from routers.injection.ssi.endpoints import router as ssi_router
from routers.file_ops.path_traversal_absolute.endpoints import router as path_traversal_absolute_router
from routers.injection.command_injection_blind.endpoints import router as command_injection_blind_router
from routers.sql_truncation.endpoints import router as sql_truncation_router
from routers.logic.graphql_batching.endpoints import router as graphql_batching_router
from routers.client_side.jsonp.endpoints import router as jsonp_router
from routers.data_exposure.weak_random.endpoints import router as weak_random_router
from routers.misconfiguration.cache_poisoning.endpoints import router as cache_poisoning_router
from routers.misconfiguration.x_forwarded_for.endpoints import router as x_forwarded_for_router
from routers.misconfiguration.method_tampering.endpoints import router as method_tampering_router
from routers.request_forgery.cswsh.endpoints import router as cswsh_router
from routers.auth.weak_password.endpoints import router as weak_password_router
from routers.logic.business_logic.endpoints import router as business_logic_router
from routers.auth.insecure_cookie.endpoints import router as insecure_cookie_router
from routers.request_forgery.ssrf_bypass.endpoints import router as ssrf_bypass_router
from routers.injection.log_injection.endpoints import router as log_injection_router
from routers.injection.format_string.endpoints import router as format_string_router
from routers.logic.redos.endpoints import router as redos_router
from routers.misconfiguration.cors_null.endpoints import router as cors_null_router
from routers.misconfiguration.mime_sniffing.endpoints import router as mime_sniffing_router
from routers.auth.jwt_jku.endpoints import router as jwt_jku_router
from routers.request_forgery.csrf_get.endpoints import router as csrf_get_router
from routers.data_exposure.sensitive_cache.endpoints import router as sensitive_cache_router
from routers.misconfiguration.graphql_introspection.endpoints import router as graphql_introspection_router
from routers.misconfiguration.tech_stack_leak.endpoints import router as tech_stack_leak_router
from routers.request_forgery.ssrf_dns_rebinding.endpoints import router as ssrf_dns_rebinding_router
from routers.access_control.bola_graphql.endpoints import router as bola_graphql_router
from routers.client_side.xss_svg.endpoints import router as xss_svg_router
from routers.injection.sqli_error.endpoints import router as sqli_error_router
from routers.injection.xss_stored_advanced.endpoints import router as xss_stored_advanced_router
from routers.auth.auth_brute_force.endpoints import router as auth_brute_force_router
from routers.access_control.idor_write.endpoints import router as idor_write_router
from routers.injection.crlf_advanced.endpoints import router as crlf_advanced_router
from routers.request_forgery.ssrf_internal.endpoints import router as ssrf_internal_router
from routers.file_ops.file_upload_advanced.endpoints import router as file_upload_advanced_router
from routers.access_control.api_ma_advanced.endpoints import router as api_ma_advanced_router
from routers.injection.xxe_advanced.endpoints import router as xxe_advanced_router
from routers.request_forgery.ssrf_cloud.endpoints import router as ssrf_cloud_router
from routers.file_ops.path_traversal_relative.endpoints import router as path_traversal_relative_router
from routers.auth.auth_timing.endpoints import router as auth_timing_router
from routers.injection.cmd_oob.endpoints import router as cmd_oob_router
from routers.misconfiguration.cors_regex.endpoints import router as cors_regex_router
from routers.injection.nosqli_blind.endpoints import router as nosqli_blind_router
from routers.auth.jwt_alg_confusion.endpoints import router as jwt_alg_confusion_router
from routers.client_side.xss_mutation.endpoints import router as xss_mutation_router
from routers.injection.ssti_advanced.endpoints import router as ssti_advanced_router
from routers.auth.oauth_state.endpoints import router as oauth_state_router

app = FastAPI(title="Valayam Mock Vulnerability Server", description="A scalable mock server for E2E scanner testing.")

# Include all modular routers
app.include_router(cors_router)
app.include_router(graphql_router)
app.include_router(oauth_router)
app.include_router(sqli_router)
app.include_router(xss_router)
app.include_router(lfi_router)
app.include_router(ssrf_router)
app.include_router(osci_router)
app.include_router(idor_router)
app.include_router(jwt_router)
app.include_router(open_redirect_router)
app.include_router(xxe_router)
app.include_router(hpp_router)
app.include_router(bac_router)
app.include_router(ssti_router)
app.include_router(deserialization_router)
app.include_router(csrf_router)
app.include_router(mass_assignment_router)
app.include_router(auth_bypass_router)
app.include_router(debug_router)
app.include_router(crypto_router)
app.include_router(host_header_router)
app.include_router(file_upload_router)
app.include_router(rate_limiting_router)
app.include_router(xpath_router)
app.include_router(ldap_router)
app.include_router(nosqli_router)
app.include_router(crlf_router)
app.include_router(yaml_deserialization_router)
app.include_router(zip_slip_router)
app.include_router(jwt_weak_router)
app.include_router(bfla_router)
app.include_router(clickjacking_router)
app.include_router(ssrf_blind_router)
app.include_router(xss_dom_router)
app.include_router(csv_injection_router)
app.include_router(graphql_dos_router)
app.include_router(open_redirect_dom_router)
app.include_router(jwt_kid_router)
app.include_router(session_fixation_router)
app.include_router(race_condition_router)
app.include_router(http_smuggling_router)
app.include_router(xst_router)
app.include_router(xxe_dos_router)
app.include_router(ssti_client_router)
app.include_router(ssi_router)
app.include_router(path_traversal_absolute_router)
app.include_router(command_injection_blind_router)
app.include_router(sql_truncation_router)
app.include_router(graphql_batching_router)
app.include_router(jsonp_router)
app.include_router(weak_random_router)
app.include_router(cache_poisoning_router)
app.include_router(x_forwarded_for_router)
app.include_router(oauth_implicit_router)
app.include_router(method_tampering_router)
app.include_router(cswsh_router)
app.include_router(weak_password_router)
app.include_router(business_logic_router)
app.include_router(insecure_cookie_router)
app.include_router(ssrf_bypass_router)
app.include_router(log_injection_router)
app.include_router(format_string_router)
app.include_router(redos_router)
app.include_router(cors_null_router)
app.include_router(mime_sniffing_router)
app.include_router(jwt_jku_router)
app.include_router(csrf_get_router)
app.include_router(sensitive_cache_router)
app.include_router(graphql_introspection_router)
app.include_router(tech_stack_leak_router)
app.include_router(ssrf_dns_rebinding_router)
app.include_router(bola_graphql_router)
app.include_router(xss_svg_router)
app.include_router(xxe_oob_router)
app.include_router(sqli_error_router)
app.include_router(xss_stored_advanced_router)
app.include_router(auth_brute_force_router)
app.include_router(idor_write_router)
app.include_router(crlf_advanced_router)
app.include_router(ssrf_internal_router)
app.include_router(file_upload_advanced_router)
app.include_router(api_ma_advanced_router)
app.include_router(xxe_advanced_router)
app.include_router(crypto_padding_router)
app.include_router(ssrf_cloud_router)
app.include_router(path_traversal_relative_router)
app.include_router(auth_timing_router)
app.include_router(cmd_oob_router)
app.include_router(cors_regex_router)
app.include_router(nosqli_blind_router)
app.include_router(jwt_alg_confusion_router)
app.include_router(xss_mutation_router)
app.include_router(ssti_advanced_router)
app.include_router(oauth_state_router)

@app.get("/")
async def root():
    return {"message": "Valayam Mock Server is running. Visit /docs for the API Swagger documentation."}

if __name__ == "__main__":
    print("[*] Starting Valayam Mock Vulnerability Server on port 8111...")
    uvicorn.run("app:app", host="127.0.0.1", port=8111, reload=True)
