// SPDX-License-Identifier: Apache-2.0
//! Concrete mTLS gRPC services for the internal gateway and host-agent contracts.
//!
//! The services deliberately keep their state small and explicit.  Server applications can wrap
//! these implementations or use the generated traits directly when they need durable storage;
//! this module provides a bounded, authenticated transport that is useful for wiring and tests.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use prost_types::Timestamp;
use thiserror::Error;
use tonic::{
    Request, Response, Status,
    transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig},
};

use crate::proto::{
    self,
    spl::{
        agent::v1::{
            AgentEvent, ConfigurationReportRequest, ConfigurationReportResponse, EnrollRequest,
            EnrollResponse, HeartbeatRequest as AgentHeartbeatRequest,
            HeartbeatResponse as AgentHeartbeatResponse, HostCertificateRequest,
            HostCertificateResponse, SubscribeRequest as AgentSubscribeRequest,
            agent_server::Agent,
        },
        gateway::v1::{
            ControlEvent, HeartbeatRequest, HeartbeatResponse, RecordingKeyRequest,
            RecordingKeyResponse, RegisterRequest, RegisterResponse, SessionEventRequest,
            SessionEventResponse, SubmitAuditRequest, SubmitAuditResponse, control_server::Control,
        },
    },
};

const MAX_ID_BYTES: usize = 36;
const MAX_VERSION_BYTES: usize = 128;
const MAX_CSR_BYTES: usize = 64 * 1024;
const MAX_DETAILS_BYTES: usize = 64 * 1024;
const MAX_AUDIT_EVENTS: usize = 256;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_SESSION_ID_BYTES: usize = 256;
const MAX_DOMAIN_BYTES: usize = 253;

/// Error returned while constructing an mTLS configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MtlsConfigError {
    /// A required PEM or domain value was empty.
    #[error("mTLS {0} must not be empty")]
    Empty(&'static str),
    /// The server name exceeded the DNS wire bound.
    #[error("mTLS domain exceeds 253 bytes")]
    DomainTooLong,
}

/// Build a tonic server configuration that requires a client certificate signed by `client_ca`.
///
/// # Errors
///
/// Returns [`MtlsConfigError::Empty`] when a required PEM value is empty.
pub fn server_tls_config(
    certificate_chain_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<ServerTlsConfig, MtlsConfigError> {
    require_non_empty(certificate_chain_pem, "server certificate")?;
    require_non_empty(private_key_pem, "server private key")?;
    require_non_empty(client_ca_pem, "client CA")?;
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate_chain_pem, private_key_pem))
        .client_ca_root(Certificate::from_pem(client_ca_pem)))
}

/// Build a tonic client configuration with a client certificate and private key.
///
/// # Errors
///
/// Returns [`MtlsConfigError::Empty`] for missing PEM values and [`MtlsConfigError::DomainTooLong`]
/// for an oversized server name.
pub fn client_tls_config(
    ca_pem: &[u8],
    client_certificate_pem: &[u8],
    client_private_key_pem: &[u8],
    domain: &str,
) -> Result<ClientTlsConfig, MtlsConfigError> {
    require_non_empty(ca_pem, "server CA")?;
    require_non_empty(client_certificate_pem, "client certificate")?;
    require_non_empty(client_private_key_pem, "client private key")?;
    validate_domain(domain)?;
    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .identity(Identity::from_pem(client_certificate_pem, client_private_key_pem))
        .domain_name(domain))
}

fn require_non_empty(value: &[u8], label: &'static str) -> Result<(), MtlsConfigError> {
    if value.is_empty() { Err(MtlsConfigError::Empty(label)) } else { Ok(()) }
}

fn validate_domain(domain: &str) -> Result<(), MtlsConfigError> {
    if domain.is_empty() {
        return Err(MtlsConfigError::Empty("domain"));
    }
    if domain.len() > MAX_DOMAIN_BYTES {
        return Err(MtlsConfigError::DomainTooLong);
    }
    Ok(())
}

/// In-memory state used by [`ControlService`].
#[derive(Clone, Debug, Default)]
pub struct ControlState {
    /// Current policy version returned by registration and heartbeat.
    pub policy_version: u64,
    /// Events delivered to subscribers after their cursor.
    pub events: Vec<ControlEvent>,
    /// Optional encrypted recording key returned to authorized callers.
    pub encrypted_recording_key: Vec<u8>,
    /// Number of accepted audit records.
    pub accepted_audits: u64,
}

/// Bounded concrete implementation of the gateway control-plane service.
#[derive(Clone, Debug)]
pub struct ControlService {
    state: Arc<Mutex<ControlState>>,
    registration: RegisterResponse,
}

impl ControlService {
    /// Construct an empty service with the supplied policy version.
    #[must_use]
    pub fn new(policy_version: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(ControlState { policy_version, ..Default::default() })),
            registration: RegisterResponse::default(),
        }
    }

    /// Construct a service with certificate material returned by `Register`.
    #[must_use]
    pub fn with_registration(
        policy_version: u64,
        certificate_chain: Vec<u8>,
        gateway_host_ca: Vec<u8>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ControlState { policy_version, ..Default::default() })),
            registration: RegisterResponse {
                certificate_chain,
                gateway_host_ca,
                policy_version,
                ..Default::default()
            },
        }
    }

    /// Append an event for future subscribers.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceStateError::Poisoned`] if a previous state access panicked.
    pub fn push_event(&self, event: ControlEvent) -> Result<(), ServiceStateError> {
        let mut state = self.state.lock().map_err(|_| ServiceStateError::Poisoned)?;
        state.events.push(event);
        Ok(())
    }

    /// Set the bounded encrypted recording key returned by future requests.
    ///
    /// # Errors
    ///
    /// Returns a bound error when the key exceeds 4096 bytes, or a poisoned-state error when the
    /// state mutex cannot be acquired.
    pub fn set_recording_key(&self, key: Vec<u8>) -> Result<(), ServiceStateError> {
        if key.len() > 4096 {
            return Err(ServiceStateError::Bound("recording key", 4096));
        }
        let mut state = self.state.lock().map_err(|_| ServiceStateError::Poisoned)?;
        state.encrypted_recording_key = key;
        Ok(())
    }

    /// Return the number of accepted audit records.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceStateError::Poisoned`] if the state mutex cannot be acquired.
    pub fn accepted_audits(&self) -> Result<u64, ServiceStateError> {
        Ok(self.state.lock().map_err(|_| ServiceStateError::Poisoned)?.accepted_audits)
    }
}

/// In-memory state used by [`AgentService`].
#[derive(Clone, Debug, Default)]
pub struct AgentState {
    /// Current policy version returned by enrollment and heartbeat.
    pub policy_version: u64,
    /// Events delivered to subscribers after their cursor.
    pub events: Vec<AgentEvent>,
    /// Number of accepted configuration reports.
    pub configuration_reports: u64,
}

/// Bounded concrete implementation of the host-agent control-plane service.
#[derive(Clone, Debug)]
pub struct AgentService {
    state: Arc<Mutex<AgentState>>,
    enrollment: EnrollResponse,
}

impl AgentService {
    /// Construct an empty service with the supplied policy version.
    #[must_use]
    pub fn new(policy_version: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(AgentState { policy_version, ..Default::default() })),
            enrollment: EnrollResponse::default(),
        }
    }

    /// Construct a service with certificate and policy material returned by `Enroll`.
    #[must_use]
    pub fn with_enrollment(
        policy_version: u64,
        certificate_chain: Vec<u8>,
        user_ca: Vec<u8>,
        revoked_krl: Vec<u8>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(AgentState { policy_version, ..Default::default() })),
            enrollment: EnrollResponse {
                certificate_chain,
                user_ca,
                revoked_krl,
                policy_version,
                ..Default::default()
            },
        }
    }

    /// Append an event for future subscribers.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceStateError::Poisoned`] if a previous state access panicked.
    pub fn push_event(&self, event: AgentEvent) -> Result<(), ServiceStateError> {
        let mut state = self.state.lock().map_err(|_| ServiceStateError::Poisoned)?;
        state.events.push(event);
        Ok(())
    }

    /// Return the number of accepted configuration reports.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceStateError::Poisoned`] if the state mutex cannot be acquired.
    pub fn configuration_reports(&self) -> Result<u64, ServiceStateError> {
        Ok(self.state.lock().map_err(|_| ServiceStateError::Poisoned)?.configuration_reports)
    }
}

/// State-management failure from a concrete service.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceStateError {
    /// The state mutex was poisoned after a panic.
    #[error("service state mutex is poisoned")]
    Poisoned,
    /// A configured value exceeded its wire bound.
    #[error("{0} exceeds {1} bytes")]
    Bound(&'static str, usize),
}

type ControlStream = tokio_stream::Iter<std::vec::IntoIter<Result<ControlEvent, Status>>>;
type AgentStream = tokio_stream::Iter<std::vec::IntoIter<Result<AgentEvent, Status>>>;

#[tonic::async_trait]
impl Control for ControlService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        validate_gateway_id(&request.get_ref().gateway_id)?;
        validate_gateway_id(&request.get_ref().network_id)?;
        validate_bytes(&request.get_ref().join_token, 4096, "join token")?;
        validate_bytes(
            &request.get_ref().certificate_signing_request,
            MAX_CSR_BYTES,
            "certificate signing request",
        )?;
        validate_text(&request.get_ref().version, MAX_VERSION_BYTES, "version")?;
        if let Some(load) = &request.get_ref().load {
            validate_load(load.active_sessions, load.pending_sessions, load.cpu_millis)?;
        }
        Ok(Response::new(self.registration.clone()))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        validate_gateway_id(&request.get_ref().gateway_id)?;
        if let Some(load) = &request.get_ref().load {
            validate_load(load.active_sessions, load.pending_sessions, load.cpu_millis)?;
        }
        let policy_version = self
            .state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .policy_version;
        Ok(Response::new(HeartbeatResponse {
            policy_version,
            next_deadline: Some(future_timestamp(Duration::from_secs(30))),
        }))
    }

    type SubscribeStream = ControlStream;

    async fn subscribe(
        &self,
        request: Request<proto::spl::gateway::v1::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        validate_gateway_id(&request.get_ref().gateway_id)?;
        let after = request.get_ref().after_event_id;
        let events = self
            .state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .events
            .iter()
            .filter(|event| event.event_id > after)
            .cloned()
            .map(Ok)
            .collect::<Vec<_>>();
        Ok(Response::new(tokio_stream::iter(events)))
    }

    async fn request_recording_key(
        &self,
        request: Request<RecordingKeyRequest>,
    ) -> Result<Response<RecordingKeyResponse>, Status> {
        validate_session_id(&request.get_ref().session_id)?;
        validate_bytes(
            &request.get_ref().gateway_session_public_key,
            512,
            "gateway session public key",
        )?;
        let key = self
            .state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .encrypted_recording_key
            .clone();
        Ok(Response::new(RecordingKeyResponse {
            encrypted_recording_key: key,
            expires_at: Some(future_timestamp(Duration::from_secs(300))),
        }))
    }

    async fn report_session_event(
        &self,
        request: Request<SessionEventRequest>,
    ) -> Result<Response<SessionEventResponse>, Status> {
        validate_session_id(&request.get_ref().session_id)?;
        validate_gateway_id(&request.get_ref().gateway_id)?;
        if request.get_ref().state == 0 {
            return Err(Status::invalid_argument("session state is required"));
        }
        validate_bytes(&request.get_ref().details, MAX_DETAILS_BYTES, "session details")?;
        Ok(Response::new(SessionEventResponse {}))
    }

    async fn submit_audit(
        &self,
        request: Request<SubmitAuditRequest>,
    ) -> Result<Response<SubmitAuditResponse>, Status> {
        validate_gateway_id(&request.get_ref().gateway_id)?;
        if request.get_ref().event.len() > MAX_AUDIT_EVENTS {
            return Err(Status::invalid_argument("audit event count exceeds 256"));
        }
        for event in &request.get_ref().event {
            validate_bytes(event, MAX_EVENT_BYTES, "audit event")?;
        }
        let accepted =
            u32::try_from(request.get_ref().event.len()).expect("audit count is bounded");
        self.state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .accepted_audits += u64::from(accepted);
        Ok(Response::new(SubmitAuditResponse { accepted }))
    }
}

#[tonic::async_trait]
impl Agent for AgentService {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        validate_gateway_id(&request.get_ref().host_id)?;
        validate_bytes(&request.get_ref().join_token, 4096, "join token")?;
        validate_bytes(
            &request.get_ref().certificate_signing_request,
            MAX_CSR_BYTES,
            "certificate signing request",
        )?;
        validate_text(&request.get_ref().agent_version, MAX_VERSION_BYTES, "agent version")?;
        validate_text(&request.get_ref().platform, 64, "platform")?;
        validate_text(&request.get_ref().sshd_version, MAX_VERSION_BYTES, "sshd version")?;
        Ok(Response::new(self.enrollment.clone()))
    }

    async fn heartbeat(
        &self,
        request: Request<AgentHeartbeatRequest>,
    ) -> Result<Response<AgentHeartbeatResponse>, Status> {
        validate_gateway_id(&request.get_ref().host_id)?;
        let status = request
            .get_ref()
            .status
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("agent status is required"))?;
        validate_text(&status.agent_version, MAX_VERSION_BYTES, "agent version")?;
        validate_text(&status.sshd_version, MAX_VERSION_BYTES, "sshd version")?;
        validate_text(&status.configuration_state, 64, "configuration state")?;
        let policy_version = self
            .state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .policy_version;
        Ok(Response::new(AgentHeartbeatResponse {
            policy_version,
            next_deadline: Some(future_timestamp(Duration::from_secs(30))),
        }))
    }

    type SubscribeStream = AgentStream;

    async fn subscribe(
        &self,
        request: Request<AgentSubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        validate_gateway_id(&request.get_ref().host_id)?;
        let after = request.get_ref().after_event_id;
        let events = self
            .state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .events
            .iter()
            .filter(|event| event.event_id > after)
            .cloned()
            .map(Ok)
            .collect::<Vec<_>>();
        Ok(Response::new(tokio_stream::iter(events)))
    }

    async fn request_host_certificate(
        &self,
        request: Request<HostCertificateRequest>,
    ) -> Result<Response<HostCertificateResponse>, Status> {
        validate_gateway_id(&request.get_ref().host_id)?;
        validate_bytes(&request.get_ref().host_public_key, 16 * 1024, "host public key")?;
        if request.get_ref().principals.len() > 64 {
            return Err(Status::invalid_argument("principal count exceeds 64"));
        }
        for principal in &request.get_ref().principals {
            validate_text(principal, 256, "principal")?;
        }
        Ok(Response::new(HostCertificateResponse::default()))
    }

    async fn report_configuration(
        &self,
        request: Request<ConfigurationReportRequest>,
    ) -> Result<Response<ConfigurationReportResponse>, Status> {
        validate_gateway_id(&request.get_ref().host_id)?;
        if request.get_ref().state == 0 {
            return Err(Status::invalid_argument("configuration state is required"));
        }
        validate_text(&request.get_ref().detail, 4096, "configuration detail")?;
        self.state
            .lock()
            .map_err(|_| Status::internal("service state unavailable"))?
            .configuration_reports += 1;
        Ok(Response::new(ConfigurationReportResponse {}))
    }
}

#[allow(clippy::result_large_err)] // Match the tonic service boundary without boxing its Status.
fn validate_gateway_id(value: &str) -> Result<(), Status> {
    validate_text(value, MAX_ID_BYTES, "identifier")?;
    let bytes = value.as_bytes();
    if value.len() != MAX_ID_BYTES || [8, 13, 18, 23].iter().any(|&index| bytes[index] != b'-') {
        return Err(Status::invalid_argument("identifier must be a lowercase UUID"));
    }
    if uuid::Uuid::parse_str(value).is_err() || value != value.to_ascii_lowercase() {
        return Err(Status::invalid_argument("identifier must be a lowercase UUID"));
    }
    Ok(())
}

#[allow(clippy::result_large_err)] // Match the tonic service boundary without boxing its Status.
fn validate_session_id(value: &str) -> Result<(), Status> {
    validate_text(value, MAX_SESSION_ID_BYTES, "session id")
}

#[allow(clippy::result_large_err)] // Match the tonic service boundary without boxing its Status.
fn validate_text(value: &str, max: usize, label: &'static str) -> Result<(), Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{label} is required")));
    }
    if value.len() > max {
        return Err(Status::invalid_argument(format!("{label} exceeds {max} bytes")));
    }
    Ok(())
}

#[allow(clippy::result_large_err)] // Match the tonic service boundary without boxing its Status.
fn validate_bytes(value: &[u8], max: usize, label: &'static str) -> Result<(), Status> {
    if value.is_empty() {
        return Err(Status::invalid_argument(format!("{label} is required")));
    }
    if value.len() > max {
        return Err(Status::invalid_argument(format!("{label} exceeds {max} bytes")));
    }
    Ok(())
}

#[allow(clippy::result_large_err)] // Match the tonic service boundary without boxing its Status.
fn validate_load(active: u32, pending: u32, cpu_millis: u32) -> Result<(), Status> {
    if active > 1_000_000 || pending > 1_000_000 || cpu_millis > 100_000 {
        return Err(Status::invalid_argument("load exceeds its bounds"));
    }
    Ok(())
}

fn future_timestamp(offset: Duration) -> Timestamp {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default() + offset;
    Timestamp {
        seconds: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(now.subsec_nanos()).expect("subsecond nanoseconds fit in i32"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Channel, Endpoint, Server};

    mod test_certs {
        include!("internal_grpc_test_certs.rs");
    }

    fn uuid() -> String {
        "018f35d4-1f8f-7e2a-9e56-7a5e8a9f11a1".into()
    }

    #[test]
    fn constructors_reject_unbounded_or_empty_tls_inputs() {
        assert!(matches!(
            server_tls_config(b"", b"key", b"ca"),
            Err(MtlsConfigError::Empty("server certificate"))
        ));
        assert!(matches!(
            client_tls_config(b"ca", b"cert", b"key", ""),
            Err(MtlsConfigError::Empty("domain"))
        ));
        assert!(matches!(
            client_tls_config(b"ca", b"cert", b"key", &"a".repeat(254)),
            Err(MtlsConfigError::DomainTooLong)
        ));
    }

    #[tokio::test]
    async fn concrete_services_validate_bounds_and_cursors() {
        let service = ControlService::new(7);
        let error = service
            .heartbeat(Request::new(HeartbeatRequest {
                gateway_id: uuid(),
                load: None,
                observed_at: None,
            }))
            .await
            .expect("heartbeat")
            .into_inner();
        assert_eq!(error.policy_version, 7);
        assert!(error.next_deadline.is_some());

        service
            .push_event(ControlEvent { event_id: 2, issued_at: None, event: None })
            .expect("event");
        let stream = service
            .subscribe(Request::new(proto::spl::gateway::v1::SubscribeRequest {
                gateway_id: uuid(),
                after_event_id: 1,
            }))
            .await
            .expect("subscribe")
            .into_inner();
        let events = tokio_stream::StreamExt::collect::<Vec<_>>(stream).await;
        assert_eq!(events.len(), 1);

        let error = service
            .heartbeat(Request::new(HeartbeatRequest {
                gateway_id: "bad".into(),
                load: None,
                observed_at: None,
            }))
            .await
            .expect_err("invalid UUID");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn mtls_accepts_signed_client_and_rejects_missing_client_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = server_tls_config(
            test_certs::SERVER_CERT.as_bytes(),
            test_certs::SERVER_KEY.as_bytes(),
            test_certs::CA_CERT.as_bytes(),
        )
        .expect("server tls");
        let service = ControlService::new(11);
        let task = tokio::spawn(
            Server::builder()
                .tls_config(server_config)
                .expect("server config")
                .add_service(proto::spl::gateway::v1::control_server::ControlServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        let missing_identity =
            Endpoint::from_shared(format!("https://localhost:{}", address.port()))
                .expect("endpoint")
                .tls_config(
                    ClientTlsConfig::new()
                        .ca_certificate(Certificate::from_pem(test_certs::CA_CERT.as_bytes()))
                        .domain_name("localhost"),
                )
                .expect("client tls");
        let missing_channel = missing_identity.connect().await.expect("channel setup");
        let mut missing_client =
            proto::spl::gateway::v1::control_client::ControlClient::new(missing_channel);
        assert!(
            missing_client
                .heartbeat(HeartbeatRequest { gateway_id: uuid(), load: None, observed_at: None })
                .await
                .is_err()
        );

        let endpoint = Endpoint::from_shared(format!("https://localhost:{}", address.port()))
            .expect("endpoint")
            .tls_config(
                client_tls_config(
                    test_certs::CA_CERT.as_bytes(),
                    test_certs::CLIENT_CERT.as_bytes(),
                    test_certs::CLIENT_KEY.as_bytes(),
                    "localhost",
                )
                .expect("client tls"),
            )
            .expect("endpoint tls");
        let channel: Channel = endpoint.connect().await.expect("mTLS channel");
        let mut client = proto::spl::gateway::v1::control_client::ControlClient::new(channel);
        let response = client
            .heartbeat(HeartbeatRequest { gateway_id: uuid(), load: None, observed_at: None })
            .await
            .expect("authenticated heartbeat");
        assert_eq!(response.into_inner().policy_version, 11);
        task.abort();
    }
}
