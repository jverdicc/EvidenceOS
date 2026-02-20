use std::time::{Duration, Instant};

use evidenceos_daemon::auth::{AuthConfig, RequestGuard};
use evidenceos_daemon::server::EvidenceOsService;
use evidenceos_protocol::pb;
use evidenceos_protocol::pb::evidence_os_client::EvidenceOsClient;
use evidenceos_protocol::pb::evidence_os_server::EvidenceOsServer;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};
use tonic::{Code, Request};

struct TestPki {
    server_cert_pem: String,
    server_key_pem: String,
    ca_cert_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn generate_test_pki() -> TestPki {
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "evidenceos-test-ca");
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_issuer = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::CommonName, "localhost");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.distinguished_name = server_dn;
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer, &ca_key)
        .expect("server cert");

    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "evidenceos-test-client");
    let mut client_params = CertificateParams::new(vec![]).expect("client params");
    client_params.distinguished_name = client_dn;
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_issuer, &ca_key)
        .expect("client cert");

    TestPki {
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        ca_cert_pem: ca_issuer.pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

async fn start_server(
    data_dir: &str,
    tls: Option<ServerTlsConfig>,
    guard: Option<RequestGuard>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let svc = EvidenceOsService::build(data_dir).expect("service");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let incoming = TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        let mut builder = Server::builder();
        if let Some(tls_cfg) = tls {
            builder = builder.tls_config(tls_cfg).expect("tls config");
        }
        match guard {
            Some(interceptor) => builder
                .add_service(EvidenceOsServer::with_interceptor(svc, interceptor))
                .serve_with_incoming(incoming)
                .await
                .expect("server run"),
            None => builder
                .add_service(EvidenceOsServer::new(svc))
                .serve_with_incoming(incoming)
                .await
                .expect("server run"),
        }
    });

    (addr, handle)
}

async fn wait_until_ready(addr: std::net::SocketAddr, tls: Option<ClientTlsConfig>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let endpoint = Channel::from_shared(match tls.is_some() {
            true => format!("https://{addr}"),
            false => format!("http://{addr}"),
        })
        .expect("endpoint")
        .connect_timeout(Duration::from_millis(200));

        let channel = match tls.clone() {
            Some(cfg) => {
                endpoint
                    .tls_config(cfg)
                    .expect("tls client config")
                    .connect()
                    .await
            }
            None => endpoint.connect().await,
        };

        if let Ok(ch) = channel {
            let mut client = EvidenceOsClient::new(ch);
            if client.health(pb::HealthRequest {}).await.is_ok() {
                return;
            }
        }
        tokio::task::yield_now().await;
    }
    panic!("server did not become ready");
}

#[tokio::test]
async fn tls_required_rejects_plaintext() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let pki = generate_test_pki();

    let tls = ServerTlsConfig::new().identity(Identity::from_pem(
        pki.server_cert_pem.clone(),
        pki.server_key_pem.clone(),
    ));
    let (addr, handle) = start_server(&data_dir.to_string_lossy(), Some(tls), None).await;

    let tls_client = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pki.ca_cert_pem.clone()))
        .domain_name("localhost");
    wait_until_ready(addr, Some(tls_client)).await;

    let mut plaintext = EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("plaintext channel");
    let err = plaintext
        .health(pb::HealthRequest {})
        .await
        .expect_err("plaintext must fail");
    assert_eq!(err.code(), Code::Unavailable);

    handle.abort();
}

#[tokio::test]
async fn mtls_rejects_no_client_cert() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");
    let pki = generate_test_pki();

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            pki.server_cert_pem.clone(),
            pki.server_key_pem.clone(),
        ))
        .client_ca_root(Certificate::from_pem(pki.ca_cert_pem.clone()));
    let (addr, handle) = start_server(&data_dir.to_string_lossy(), Some(tls), None).await;

    let no_client_cert = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pki.ca_cert_pem.clone()))
        .domain_name("localhost");
    let channel = Channel::from_shared(format!("https://{addr}"))
        .expect("endpoint")
        .tls_config(no_client_cert)
        .expect("tls")
        .connect()
        .await;
    assert!(channel.is_err());

    let wrong_pki = generate_test_pki();
    let wrong_client_cert = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pki.ca_cert_pem))
        .identity(Identity::from_pem(
            wrong_pki.client_cert_pem,
            wrong_pki.client_key_pem,
        ))
        .domain_name("localhost");
    let wrong_channel = Channel::from_shared(format!("https://{addr}"))
        .expect("endpoint")
        .tls_config(wrong_client_cert)
        .expect("tls")
        .connect()
        .await;
    assert!(wrong_channel.is_err());

    handle.abort();
}

#[tokio::test]
async fn auth_rejects_missing_token() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let guard = RequestGuard::new(
        Some(AuthConfig::BearerToken("top-secret".to_string())),
        None,
    );
    let (addr, handle) = start_server(&data_dir.to_string_lossy(), None, Some(guard)).await;

    let mut client = EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");
    let err = client
        .health(pb::HealthRequest {})
        .await
        .expect_err("missing token must fail");
    assert_eq!(err.code(), Code::Unauthenticated);

    handle.abort();
}

#[tokio::test]
async fn auth_accepts_valid_token() {
    let dir = TempDir::new().expect("tmp");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("mkdir");

    let guard = RequestGuard::new(
        Some(AuthConfig::BearerToken("top-secret".to_string())),
        None,
    );
    let (addr, handle) = start_server(&data_dir.to_string_lossy(), None, Some(guard)).await;

    let mut client = EvidenceOsClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");
    let mut req = Request::new(pb::HealthRequest {});
    req.metadata_mut().insert(
        "authorization",
        MetadataValue::from_static("Bearer top-secret"),
    );
    let response = client
        .health(req)
        .await
        .expect("token accepted")
        .into_inner();
    assert_eq!(response.status, "SERVING");

    handle.abort();
}
