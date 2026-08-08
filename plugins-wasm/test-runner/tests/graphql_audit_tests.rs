use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use test_runner::*;

fn start_graphql_vulnerable_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 1024];
                let _ = stream.read(&mut buffer);
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 106\r\n\r\n{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"mutationType\":null,\"subscriptionType\":null,\"types\":[]}}}";
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });

    format!("http://127.0.0.1:{}", port)
}

#[test]
fn test_graphql_audit_vulnerable() {
    let wasm = build_wasm("valayam-plugin-graphql-audit");
    let target_url = start_graphql_vulnerable_server();
    let input = WasmInput {
        template: json!({"id": "graphql", "name": "GraphQL Audit"}),
        context: HashMap::from([("BaseURL".into(), target_url.clone())]),
    };
    let out = run_plugin(&wasm, &input);
    assert!(out.matched);
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.findings[0].severity, "High");
    assert!(out.findings[0].description.as_ref().unwrap().contains("GraphQL Introspection"));
}
