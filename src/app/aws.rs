use aws_config::BehaviorVersion;
use aws_sdk_sts::config::ProvideCredentials;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Deserialize, Serialize)]
pub struct K8sToken {
    pub kind: String,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub spec: HashMap<String, ()>,
    pub status: K8sTokenStatus,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct K8sTokenStatus {
    #[serde(rename = "expirationTimestamp")]
    pub expiration_timestamp: String,
    pub token: String,
}

pub struct GetEKSTokenInput {
    /// The AWS region to use for the request
    pub aws_region: String,

    /// The AWS profile to use for the request
    pub aws_profile: String,

    /// The name of the EKS cluster
    pub cluster_name: String,

    /// The session name to use when assuming the role to authenticate the K8s requests
    pub session_name: Option<String>,
}

#[derive(Error, Debug)]
pub enum GetEKSTokenError {
    #[error(
        "Credentials provider was None when trying to get credentials from the AWS shared config"
    )]
    CredentialsProviderNone,

    #[error("Unable to get credentials from the AWS credentials provider: {source}")]
    CredentialsProviderError {
        source: aws_credential_types::provider::error::CredentialsError,
    },

    #[error(
        "Failed to build the signing params for signing the authenticating with EKS: {source}"
    )]
    FailedToBuildSigningParams {
        source: aws_sigv4::sign::v4::signing_params::BuildError,
    },

    #[error("Failed to build HTTP request for authenticating to EKS: {source}")]
    FailedToBuildHttpRequest { source: http::Error },

    #[error("Failed to create signable request to sign EKS authentication request: {source}")]
    FailedToCreateSignableRequest {
        source: aws_sigv4::http_request::SigningError,
    },

    #[error("Failed to sign HTTP request for authenticating against EKS cluster: {source}")]
    FailedToSignHttpRequest {
        source: aws_sigv4::http_request::SigningError,
    },

    #[error("Failed to serialize EKS authentication token: {source}")]
    FailedToSerializeToken { source: serde_json::Error },
}

pub async fn get_eks_token(input: &GetEKSTokenInput) -> Result<String, GetEKSTokenError> {
    let session_name = if let Some(session_name) = &input.session_name {
        session_name
    } else {
        &"kashay".to_string()
    };

    let region = aws_config::Region::new(input.aws_region.clone());
    let shared_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
        .region(region)
        .profile_name(&input.aws_profile)
        .load()
        .await;

    let identity = shared_config
        .credentials_provider()
        .ok_or_else(|| GetEKSTokenError::CredentialsProviderNone)?
        .provide_credentials()
        .await
        .map_err(|source| GetEKSTokenError::CredentialsProviderError { source })?
        .into();

    let mut signing_settings = aws_sigv4::http_request::SigningSettings::default();
    signing_settings.signature_location = aws_sigv4::http_request::SignatureLocation::QueryParams;
    signing_settings.expires_in = Some(std::time::Duration::from_secs(60));
    let request_ts = chrono::Utc::now();
    let signing_params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(&input.aws_region)
        .name(session_name)
        .time(request_ts.into())
        .settings(signing_settings)
        .build()
        .map_err(|source| GetEKSTokenError::FailedToBuildSigningParams { source })?
        .into();

    let uri = "https://sts.eu-west-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15";

    let mut request = http::Request::builder()
        .uri(uri)
        .header("x-k8s-aws-id", &input.cluster_name)
        .body(())
        .map_err(|source| GetEKSTokenError::FailedToBuildHttpRequest { source })?;

    let signable_request = aws_sigv4::http_request::SignableRequest::new(
        "GET",
        uri,
        request
            .headers()
            .iter()
            .map(|(headername, headervalue)| (headername.as_str(), headervalue.to_str().unwrap())),
        aws_sigv4::http_request::SignableBody::Bytes(&[]),
    )
    .map_err(|source| GetEKSTokenError::FailedToCreateSignableRequest { source })?;

    let (signing_instructions, _signature) =
        aws_sigv4::http_request::sign(signable_request, &signing_params)
            .map_err(|source| GetEKSTokenError::FailedToSignHttpRequest { source })?
            .into_parts();

    signing_instructions.apply_to_request_http1x(&mut request);

    let uri = format!(
        "k8s-aws-v1.{}",
        URL_SAFE_NO_PAD.encode(request.uri().to_string())
    );

    let token = K8sToken {
        kind: "ExecCredential".to_string(),
        api_version: "client.authentication.k8s.io/v1beta1".to_string(),
        spec: HashMap::new(),
        status: K8sTokenStatus {
            expiration_timestamp: request_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            token: uri,
        },
    };

    serde_json::to_string(&token)
        .map_err(|source| GetEKSTokenError::FailedToSerializeToken { source })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::app::cli::CliArgs;
    use anyhow::Result;

    #[test_log::test(tokio::test)]
    async fn test_get_eks_token() -> Result<()> {
        let args = CliArgs {
            aws_profile: "kashay-test".to_string(),
            aws_region: "eu-west-2".to_string(),
            cluster_name: "test-cluster".to_string(),
            session_name: Some("kashay-test-session".to_string()),
        };
        let reqwest_client = reqwest::Client::new();
        let cluster_name = "syn-scout-k8s-playground";
        let get_eks_token_input = args.into();

        for _ in 0..9 {
            let result = get_eks_token(&get_eks_token_input).await?;

            let parsed_json: K8sToken = serde_json::from_str(&result)?;

            let token = parsed_json.status.token;
            println!("Token: {:?}", token);
            let url = URL_SAFE_NO_PAD.decode(token.replace("k8s-aws-v1.", ""))?;
            let url = std::str::from_utf8(url.as_slice())?;
            println!("Decoded to url: {:?}", url);

            let resp = reqwest_client
                .get(url)
                .header("x-k8s-aws-id", cluster_name)
                .send()
                .await?;

            let status = resp.status();
            let body = resp.text().await?;

            if status != 200 {
                println!(
                    "Request failed with http: {} and response body: {}",
                    status, &body
                );
            }

            println!(
                "Request succeeded with http: {} and response body: {}",
                status, &body
            );
        }
        Ok(())
    }
}
