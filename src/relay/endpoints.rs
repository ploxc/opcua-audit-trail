//! "Follow the target": the endpoints the gateway offers to clients are derived
//! from the upstream server's endpoints.

use opcua::crypto::SecurityPolicy;
use opcua::types::{
    ApplicationDescription, ApplicationType, EndpointDescription, LocalizedText,
    MessageSecurityMode, UAString, UserTokenPolicy, UserTokenType,
};

use super::GatewayIdentity;
use crate::config::MinSecurity;

pub const PRODUCT_URI: &str = "urn:opcua-audit-gateway";

/// User token types the gateway can pass through to the upstream server.
/// X509 and issued tokens are signed with keys the gateway does not have.
pub fn is_relayable_token(policy: &UserTokenPolicy) -> bool {
    matches!(
        policy.token_type,
        UserTokenType::Anonymous | UserTokenType::UserName
    )
}

pub fn server_description(gateway: &GatewayIdentity, url: &str) -> ApplicationDescription {
    ApplicationDescription {
        application_uri: gateway.application_uri.as_str().into(),
        product_uri: PRODUCT_URI.into(),
        application_name: LocalizedText::new("", &gateway.server_name),
        application_type: ApplicationType::Server,
        gateway_server_uri: UAString::null(),
        discovery_profile_uri: UAString::null(),
        discovery_urls: Some(vec![url.into()]),
    }
}

pub fn client_description(gateway: &GatewayIdentity) -> ApplicationDescription {
    ApplicationDescription {
        application_uri: gateway.application_uri.as_str().into(),
        product_uri: PRODUCT_URI.into(),
        application_name: LocalizedText::new("", &gateway.application_name),
        application_type: ApplicationType::Client,
        gateway_server_uri: UAString::null(),
        discovery_profile_uri: UAString::null(),
        discovery_urls: None,
    }
}

/// The endpoints offered to clients: one per upstream endpoint with a security
/// policy the gateway supports, with the gateway's URL, identity and
/// certificate, and only the user token types that can be relayed.
pub fn gateway_endpoints(
    upstream: &[EndpointDescription],
    gateway: &GatewayIdentity,
    url: &str,
) -> Vec<EndpointDescription> {
    upstream
        .iter()
        .filter(|e| {
            let policy = SecurityPolicy::from_uri(e.security_policy_uri.as_ref());
            policy != SecurityPolicy::Unknown && policy.is_supported()
        })
        .map(|e| EndpointDescription {
            endpoint_url: url.into(),
            server: server_description(gateway, url),
            server_certificate: gateway.certificate_bytes.clone(),
            security_mode: e.security_mode,
            security_policy_uri: e.security_policy_uri.clone(),
            user_identity_tokens: Some(
                e.user_identity_tokens
                    .iter()
                    .flatten()
                    .filter(|t| is_relayable_token(t))
                    .cloned()
                    .collect(),
            ),
            transport_profile_uri: e.transport_profile_uri.clone(),
            security_level: e.security_level,
        })
        .collect()
}

/// The security level of an endpoint, comparable with [`MinSecurity`].
pub fn security_of(endpoint: &EndpointDescription) -> MinSecurity {
    match (
        SecurityPolicy::from_uri(endpoint.security_policy_uri.as_ref()),
        endpoint.security_mode,
    ) {
        (SecurityPolicy::None, _) => MinSecurity::None,
        (_, MessageSecurityMode::SignAndEncrypt) => MinSecurity::SignAndEncrypt,
        (_, MessageSecurityMode::Sign) => MinSecurity::Sign,
        _ => MinSecurity::None,
    }
}

/// Drops the endpoints below the target's minimum security.
pub fn at_least(endpoints: Vec<EndpointDescription>, min: MinSecurity) -> Vec<EndpointDescription> {
    endpoints
        .into_iter()
        .filter(|e| security_of(e) >= min)
        .collect()
}

/// Security settings the server lists in its CreateSession response (which
/// arrives over the secured channel) that discovery did not return. Anything
/// here means the unauthenticated discovery answer was tampered with.
pub fn missing_from_discovery(
    server: &[EndpointDescription],
    discovered: &[EndpointDescription],
    min: MinSecurity,
) -> Option<String> {
    let missing: Vec<String> = server
        .iter()
        .filter(|s| security_of(s) >= min)
        .filter(|s| {
            !discovered.iter().any(|d| {
                d.security_mode == s.security_mode && d.security_policy_uri == s.security_policy_uri
            })
        })
        .map(|s| {
            format!(
                "{} {:?}",
                SecurityPolicy::from_uri(s.security_policy_uri.as_ref()).to_str(),
                s.security_mode
            )
        })
        .collect();
    (!missing.is_empty()).then(|| missing.join(", "))
}

/// A one-line summary of an endpoint's security, to notice changes.
pub fn summary(endpoint: &EndpointDescription) -> String {
    let thumbprint = opcua::crypto::X509::from_byte_string(&endpoint.server_certificate)
        .map(|c| c.thumbprint().as_hex_string())
        .unwrap_or_else(|_| "no certificate".into());
    let mut tokens: Vec<String> = endpoint
        .user_identity_tokens
        .iter()
        .flatten()
        .map(|t| format!("{:?}", t.token_type))
        .collect();
    tokens.sort();
    tokens.dedup();
    format!(
        "{} {:?} [{}] {}",
        SecurityPolicy::from_uri(endpoint.security_policy_uri.as_ref()).to_str(),
        endpoint.security_mode,
        thumbprint,
        tokens.join("+")
    )
}

/// The upstream endpoint to use for a client channel with this policy and mode.
pub fn matching_upstream(
    upstream: &[EndpointDescription],
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
) -> Option<&EndpointDescription> {
    upstream.iter().find(|e| {
        e.security_mode == mode
            && SecurityPolicy::from_uri(e.security_policy_uri.as_ref()) == policy
    })
}

/// Finds a user token policy by id on an endpoint.
pub fn token_policy<'a>(
    endpoint: &'a EndpointDescription,
    policy_id: &UAString,
) -> Option<&'a UserTokenPolicy> {
    endpoint
        .user_identity_tokens
        .iter()
        .flatten()
        .find(|t| &t.policy_id == policy_id)
}

/// The first token policy of the given type on an endpoint.
pub fn token_policy_of_type(
    endpoint: &EndpointDescription,
    token_type: UserTokenType,
) -> Option<&UserTokenPolicy> {
    endpoint
        .user_identity_tokens
        .iter()
        .flatten()
        .find(|t| t.token_type == token_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::crypto::{X509Data, X509};

    fn gateway() -> GatewayIdentity {
        let (cert, key) = X509::cert_and_pkey(&X509Data::sample_cert()).unwrap();
        GatewayIdentity::new(
            cert,
            key,
            "urn:gw".into(),
            "Gateway".into(),
            "Gateway - plc1".into(),
        )
    }

    fn endpoint(policy: SecurityPolicy, mode: MessageSecurityMode) -> EndpointDescription {
        EndpointDescription {
            endpoint_url: "opc.tcp://plc:4840".into(),
            security_mode: mode,
            security_policy_uri: policy.to_uri().into(),
            user_identity_tokens: Some(vec![
                UserTokenPolicy {
                    policy_id: "anon".into(),
                    token_type: UserTokenType::Anonymous,
                    ..Default::default()
                },
                UserTokenPolicy {
                    policy_id: "cert".into(),
                    token_type: UserTokenType::Certificate,
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }
    }

    #[test]
    fn mirrors_upstream_with_gateway_identity() {
        let gw = gateway();
        let upstream = vec![
            endpoint(
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::SignAndEncrypt,
            ),
            endpoint(SecurityPolicy::None, MessageSecurityMode::None),
        ];
        let ours = gateway_endpoints(&upstream, &gw, "opc.tcp://gw:4841");
        assert_eq!(ours.len(), 2);
        assert_eq!(ours[0].endpoint_url.as_ref(), "opc.tcp://gw:4841");
        assert_eq!(ours[0].server.application_uri.as_ref(), "urn:gw");
        assert_eq!(ours[0].server_certificate, gw.certificate_bytes);
        assert_eq!(ours[0].security_mode, MessageSecurityMode::SignAndEncrypt);
        // Certificate user tokens cannot be relayed.
        let tokens = ours[0].user_identity_tokens.as_ref().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, UserTokenType::Anonymous);

        let m = matching_upstream(&upstream, SecurityPolicy::None, MessageSecurityMode::None);
        assert_eq!(m.unwrap().security_mode, MessageSecurityMode::None);
    }
}
