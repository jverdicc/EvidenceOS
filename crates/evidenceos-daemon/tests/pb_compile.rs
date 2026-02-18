use evidenceos_protocol::pb;

#[tokio::test]
async fn protocol_crate_exports_client_and_server_stubs() {
    fn assert_service_trait<T: pb::evidence_os_server::EvidenceOs>() {}

    struct Dummy;

    #[tonic::async_trait]
    impl pb::evidence_os_server::EvidenceOs for Dummy {
        type WatchRevocationsStream = tokio_stream::wrappers::ReceiverStream<
            Result<pb::WatchRevocationsResponse, tonic::Status>,
        >;
        async fn health(
            &self,
            _request: tonic::Request<pb::HealthRequest>,
        ) -> Result<tonic::Response<pb::HealthResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn create_claim(
            &self,
            _request: tonic::Request<pb::CreateClaimRequest>,
        ) -> Result<tonic::Response<pb::CreateClaimResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn create_claim_v2(
            &self,
            _request: tonic::Request<pb::CreateClaimV2Request>,
        ) -> Result<tonic::Response<pb::CreateClaimV2Response>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn commit_artifacts(
            &self,
            _request: tonic::Request<pb::CommitArtifactsRequest>,
        ) -> Result<tonic::Response<pb::CommitArtifactsResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn freeze_gates(
            &self,
            _request: tonic::Request<pb::FreezeGatesRequest>,
        ) -> Result<tonic::Response<pb::FreezeGatesResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn seal_claim(
            &self,
            _request: tonic::Request<pb::SealClaimRequest>,
        ) -> Result<tonic::Response<pb::SealClaimResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn execute_claim(
            &self,
            _request: tonic::Request<pb::ExecuteClaimRequest>,
        ) -> Result<tonic::Response<pb::ExecuteClaimResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn execute_claim_v2(
            &self,
            _request: tonic::Request<pb::ExecuteClaimV2Request>,
        ) -> Result<tonic::Response<pb::ExecuteClaimV2Response>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn get_capsule(
            &self,
            _request: tonic::Request<pb::GetCapsuleRequest>,
        ) -> Result<tonic::Response<pb::GetCapsuleResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn get_public_key(
            &self,
            _request: tonic::Request<pb::GetPublicKeyRequest>,
        ) -> Result<tonic::Response<pb::GetPublicKeyResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn get_signed_tree_head(
            &self,
            _request: tonic::Request<pb::GetSignedTreeHeadRequest>,
        ) -> Result<tonic::Response<pb::GetSignedTreeHeadResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn get_inclusion_proof(
            &self,
            _request: tonic::Request<pb::GetInclusionProofRequest>,
        ) -> Result<tonic::Response<pb::GetInclusionProofResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn get_consistency_proof(
            &self,
            _request: tonic::Request<pb::GetConsistencyProofRequest>,
        ) -> Result<tonic::Response<pb::GetConsistencyProofResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn get_revocation_feed(
            &self,
            _request: tonic::Request<pb::GetRevocationFeedRequest>,
        ) -> Result<tonic::Response<pb::GetRevocationFeedResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn fetch_capsule(
            &self,
            _request: tonic::Request<pb::FetchCapsuleRequest>,
        ) -> Result<tonic::Response<pb::FetchCapsuleResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn revoke_claim(
            &self,
            _request: tonic::Request<pb::RevokeClaimRequest>,
        ) -> Result<tonic::Response<pb::RevokeClaimResponse>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }

        async fn watch_revocations(
            &self,
            _request: tonic::Request<pb::WatchRevocationsRequest>,
        ) -> Result<tonic::Response<Self::WatchRevocationsStream>, tonic::Status> {
            Err(tonic::Status::unimplemented("compile-only"))
        }
    }

    assert_service_trait::<Dummy>();
    let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:50051").connect_lazy();
    let _ = pb::evidence_os_client::EvidenceOsClient::new(channel);
}
