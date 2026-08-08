use crate::cert_auth::CertificateAuthority;
use crate::server::UiProxyServer;
use crate::state::{InterceptedRequest, ProxyRequestData, ProxyState};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use reqwest::Method as ReqwestMethod;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::oneshot;
use valayam_models::templates::http_scan::HttpRequestTemplate;
use valayam_models::templates::schema::{TemplateInfo, VulnerabilityTemplate};
use valayam_network::network::http::StealthHttpClient;

async fn handle_request(
    req: Request<Body>,
    stealth_client: Arc<StealthHttpClient>,
    ca: Arc<CertificateAuthority>,
    proxy_state: ProxyState,
) -> Result<Response<Body>, hyper::Error> {
    let uri = req.uri().to_string();
    let method = req.method().clone();

    if method == hyper::Method::CONNECT {
        println!("[MITM] Intercepting TLS CONNECT: {}", uri);
        let uri_str = uri.clone();

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let domain = uri_str.split(':').next().unwrap_or(&uri_str).to_string();
                    if let Ok(acceptor) = ca.gen_acceptor_for_domain(&domain) {
                        if let Ok(tls_stream) = acceptor.accept(upgraded).await {
                            let p_state = proxy_state.clone();
                            let service = service_fn(move |tls_req| {
                                handle_tls_request(
                                    tls_req,
                                    Arc::clone(&stealth_client),
                                    domain.clone(),
                                    p_state.clone(),
                                )
                            });

                            if let Err(e) = hyper::server::conn::Http::new()
                                .serve_connection(tls_stream, service)
                                .await
                            {
                                eprintln!("[MITM] TLS connection error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[MITM] Upgrade error: {}", e),
            }
        });

        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = hyper::StatusCode::OK;
        return Ok(resp);
    }

    process_http_please(req, stealth_client, uri, proxy_state).await
}

async fn handle_tls_request(
    req: Request<Body>,
    stealth_client: Arc<StealthHttpClient>,
    domain: String,
    proxy_state: ProxyState,
) -> Result<Response<Body>, hyper::Error> {
    let mut uri = req.uri().to_string();
    if !uri.starts_with("http") {
        uri = format!("https://{}{}", domain, uri);
    }
    process_http_please(req, stealth_client, uri, proxy_state).await
}

async fn process_http_please(
    mut req: Request<Body>,
    stealth_client: Arc<StealthHttpClient>,
    full_uri: String,
    proxy_state: ProxyState,
) -> Result<Response<Body>, hyper::Error> {
    let method = req.method().clone();
    println!("[MITM] Intercepted: {} {}", method, full_uri);

    let body_bytes = hyper::body::to_bytes(req.body_mut()).await?;
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    let req_id = uuid::Uuid::new_v4().to_string();
    let mut headers = Vec::new();
    for (k, v) in req.headers() {
        headers.push((
            k.as_str().to_string(),
            String::from_utf8_lossy(v.as_bytes()).to_string(),
        ));
    }

    let p_req = ProxyRequestData {
        id: req_id.clone(),
        method: method.to_string(),
        uri: full_uri.clone(),
        headers,
        body: body_str.clone(),
    };

    let (tx, rx) = oneshot::channel();
    proxy_state.pending_requests.insert(
        req_id.clone(),
        InterceptedRequest {
            request_data: p_req.clone(),
            tx,
        },
    );

    let final_req_data = match rx.await {
        Ok(Some(mutated)) => mutated,
        _ => {
            let _ = proxy_state.pending_requests.remove(&req_id);
            p_req
        }
    };

    let reqwest_method =
        ReqwestMethod::from_str(final_req_data.method.as_str()).unwrap_or(ReqwestMethod::GET);
    let mut req_builder = stealth_client
        .client()
        .request(reqwest_method, &final_req_data.uri);

    for (k, v) in final_req_data.headers {
        if let Ok(k_name) = reqwest::header::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(v_val) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
                if k_name != reqwest::header::HOST {
                    req_builder = req_builder.header(k_name, v_val);
                }
            }
        }
    }

    if !final_req_data.body.is_empty() {
        req_builder = req_builder.body(final_req_data.body.clone().into_bytes());
    }

    match req_builder.send().await {
        Ok(res) => {
            let _ = generate_template(
                &final_req_data.uri,
                &final_req_data.method,
                &final_req_data.body,
            )
            .await;

            let mut builder = Response::builder().status(res.status().as_u16());
            for (k, v) in res.headers() {
                if let Ok(k_name) = hyper::header::HeaderName::from_bytes(k.as_str().as_bytes()) {
                    if let Ok(v_val) = hyper::header::HeaderValue::from_bytes(v.as_bytes()) {
                        builder = builder.header(k_name, v_val);
                    }
                }
            }

            let body_bytes = res.bytes().await.unwrap_or_default();
            let body = Body::from(body_bytes);
            Ok(builder
                .body(body)
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }
        Err(e) => {
            eprintln!("[MITM] Error forwarding request: {}", e);
            let mut resp = Response::new(Body::from(format!("Proxy Error: {}", e)));
            *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}

async fn generate_template(uri: &str, method: &str, body: &str) -> std::io::Result<()> {
    let parsed_uri = match reqwest::Url::parse(uri) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };

    let domain = parsed_uri.host_str().unwrap_or("unknown");
    let path = parsed_uri.path();
    let safe_path = path.replace(['/', '.'], "_");

    let template_id = format!("mitm-{}-{}-{}", domain, method.to_lowercase(), safe_path);
    let filename = format!("./intercepted_templates/{}.yaml", template_id);

    let _ = fs::create_dir_all("./intercepted_templates").await;

    let http_req = HttpRequestTemplate {
        method: method.to_string(),
        path: path.to_string(),
        body: if body.is_empty() {
            None
        } else {
            Some(body.to_string())
        },
        headers: None,
        matchers: vec![],
        matcher_condition: "and".to_string(),
        extractors: vec![],
        attack: None,
        payloads: None,
        inject_in: None,
        follow_redirects: None,
    };

    let template = VulnerabilityTemplate {
        id: template_id.clone(),
        info: TemplateInfo {
            name: format!("Auto-generated MITM template for {}", uri),
            severity: "Info".to_string(),
            description: Some("Automatically captured via proxy".into()),
            compliance: Default::default(),
            author: None,
            tags: vec![],
        },
        auth: None,
        requests: vec![http_req],
        network: vec![],
        scripts: vec![],
        dns: vec![],
        tls: vec![],
        fuzz: vec![],
        cloud: vec![],
        logic: vec![],
        deep_analysis: vec![],
        iac_audit: vec![],
        sbom_audit: vec![],
        grpc_audit: vec![],
        graphql_audit: vec![],
        drift_detect: vec![],
        cred_monitor: vec![],
        oauth_audit: vec![],
        idp_audit: vec![],
        aws_escalate: vec![],
        azure_gcp_escalate: vec![],
        browser_audit: vec![],
        iot_audit: vec![],
        scada_audit: vec![],
        auto_redteam: vec![],
        implant_deploy: vec![],
        client_secret_audit: vec![],
        dom_redirect_audit: vec![],
        cors_audit: vec![],
        csp_audit: vec![],
        waf_bypass_verify: vec![],
        header_scorecard: vec![],
        reputation_audit: vec![],
        ct_log_audit: vec![],
        remediation_gen: vec![],
        mitre_mapping: vec![],
        container_audit: vec![],
        k8s_audit: vec![],
        sast_taint: vec![],
        sast_secrets: vec![],
        subdomain_takeover: vec![],
        port_scan: vec![],
        schema_drift: vec![],
        pii_leak_audit: vec![],
        cicd_audit: vec![],
        dependency_audit: vec![],
        easm: vec![],
        web3_audit: vec![],
        mobile_audit: vec![],
        serverless_audit: vec![],
        auto_exploit: vec![],
        ui_proxy: vec![],
        oob_interaction: false,
    };

    let yaml = serde_yaml::to_string(&template).unwrap();
    fs::write(&filename, yaml).await?;
    println!("[MITM] Generated template: {}", filename);
    Ok(())
}

pub async fn start_proxy(port: u16, stealth_client: Arc<StealthHttpClient>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let client = stealth_client;

    let ca = Arc::new(CertificateAuthority::new().expect("Failed to initialize CA"));
    let proxy_state = ProxyState::new();
    let state_clone = proxy_state.clone();
    let _ = UiProxyServer::start(port + 1, proxy_state).await;

    let make_svc = make_service_fn(move |_conn| {
        let client = Arc::clone(&client);
        let ca = Arc::clone(&ca);
        let proxy_state = state_clone.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(
                    req,
                    Arc::clone(&client),
                    Arc::clone(&ca),
                    proxy_state.clone(),
                )
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!(
        "\x1b[1;32m[+] Valayam MITM Proxy running on http://{}\x1b[0m",
        addr
    );
    println!(
        "Configure your browser to use this proxy to automatically generate Valayam templates."
    );

    if let Err(e) = server.await {
        eprintln!("[!] MITM Proxy error: {}", e);
    }
}
