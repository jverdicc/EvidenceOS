use super::*;

#[tonic::async_trait]
impl EvidenceOsV1 for EvidenceOsService {
    type WatchRevocationsStream = Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<v1::WatchRevocationsResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn health(
        &self,
        request: Request<v1::HealthRequest>,
    ) -> Result<Response<v1::HealthResponse>, Status> {
        let req_v2: v2::HealthRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::health(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_server_info(
        &self,
        request: Request<v1::GetServerInfoRequest>,
    ) -> Result<Response<v1::GetServerInfoResponse>, Status> {
        let req_v2: v2::GetServerInfoRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::get_server_info(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn create_claim(
        &self,
        request: Request<v1::CreateClaimRequest>,
    ) -> Result<Response<v1::CreateClaimResponse>, Status> {
        let req_v2: Request<v2::CreateClaimRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::create_claim(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn create_claim_v2(
        &self,
        request: Request<v1::CreateClaimV2Request>,
    ) -> Result<Response<v1::CreateClaimV2Response>, Status> {
        let req_v2: Request<v2::CreateClaimV2Request> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::create_claim_v2(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn commit_artifacts(
        &self,
        request: Request<v1::CommitArtifactsRequest>,
    ) -> Result<Response<v1::CommitArtifactsResponse>, Status> {
        let req_v2: Request<v2::CommitArtifactsRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::commit_artifacts(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn freeze(
        &self,
        request: Request<v1::FreezeRequest>,
    ) -> Result<Response<v1::FreezeResponse>, Status> {
        let req_v2: Request<v2::FreezeRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::freeze(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn freeze_gates(
        &self,
        request: Request<v1::FreezeGatesRequest>,
    ) -> Result<Response<v1::FreezeGatesResponse>, Status> {
        let req_v2: Request<v2::FreezeGatesRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::freeze_gates(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn seal(
        &self,
        request: Request<v1::SealRequest>,
    ) -> Result<Response<v1::SealResponse>, Status> {
        let req_v2: Request<v2::SealRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::seal(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn seal_claim(
        &self,
        request: Request<v1::SealClaimRequest>,
    ) -> Result<Response<v1::SealClaimResponse>, Status> {
        let req_v2: Request<v2::SealClaimRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::seal_claim(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn execute_claim(
        &self,
        request: Request<v1::ExecuteClaimRequest>,
    ) -> Result<Response<v1::ExecuteClaimResponse>, Status> {
        let req_v2: Request<v2::ExecuteClaimRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::execute_claim(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn execute_claim_v2(
        &self,
        request: Request<v1::ExecuteClaimV2Request>,
    ) -> Result<Response<v1::ExecuteClaimV2Response>, Status> {
        let req_v2: Request<v2::ExecuteClaimV2Request> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::execute_claim_v2(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_capsule(
        &self,
        request: Request<v1::GetCapsuleRequest>,
    ) -> Result<Response<v1::GetCapsuleResponse>, Status> {
        let req_v2: Request<v2::GetCapsuleRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::get_capsule(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_public_key(
        &self,
        request: Request<v1::GetPublicKeyRequest>,
    ) -> Result<Response<v1::GetPublicKeyResponse>, Status> {
        let req_v2: v2::GetPublicKeyRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::get_public_key(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_signed_tree_head(
        &self,
        request: Request<v1::GetSignedTreeHeadRequest>,
    ) -> Result<Response<v1::GetSignedTreeHeadResponse>, Status> {
        let req_v2: v2::GetSignedTreeHeadRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::get_signed_tree_head(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_inclusion_proof(
        &self,
        request: Request<v1::GetInclusionProofRequest>,
    ) -> Result<Response<v1::GetInclusionProofResponse>, Status> {
        let req_v2: Request<v2::GetInclusionProofRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::get_inclusion_proof(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_consistency_proof(
        &self,
        request: Request<v1::GetConsistencyProofRequest>,
    ) -> Result<Response<v1::GetConsistencyProofResponse>, Status> {
        let req_v2: Request<v2::GetConsistencyProofRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::get_consistency_proof(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn get_revocation_feed(
        &self,
        request: Request<v1::GetRevocationFeedRequest>,
    ) -> Result<Response<v1::GetRevocationFeedResponse>, Status> {
        let req_v2: v2::GetRevocationFeedRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::get_revocation_feed(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn fetch_capsule(
        &self,
        request: Request<v1::FetchCapsuleRequest>,
    ) -> Result<Response<v1::FetchCapsuleResponse>, Status> {
        let req_v2: Request<v2::FetchCapsuleRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::fetch_capsule(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn revoke_claim(
        &self,
        request: Request<v1::RevokeClaimRequest>,
    ) -> Result<Response<v1::RevokeClaimResponse>, Status> {
        let req_v2: Request<v2::RevokeClaimRequest> = transcode_request(request)?;
        let response = <Self as EvidenceOsV2>::revoke_claim(self, req_v2).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn grant_credit(
        &self,
        request: Request<v1::GrantCreditRequest>,
    ) -> Result<Response<v1::GrantCreditResponse>, Status> {
        let req_v2: v2::GrantCreditRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::grant_credit(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }

    async fn set_credit_limit(
        &self,
        request: Request<v1::SetCreditLimitRequest>,
    ) -> Result<Response<v1::SetCreditLimitResponse>, Status> {
        let req_v2: v2::SetCreditLimitRequest = transcode_message(request.into_inner())?;
        let response = <Self as EvidenceOsV2>::set_credit_limit(self, Request::new(req_v2)).await?;
        Ok(Response::new(transcode_message(response.into_inner())?))
    }
    async fn watch_revocations(
        &self,
        request: Request<v1::WatchRevocationsRequest>,
    ) -> Result<Response<Self::WatchRevocationsStream>, Status> {
        let req_v2: v2::WatchRevocationsRequest = transcode_message(request.into_inner())?;
        let response =
            <Self as EvidenceOsV2>::watch_revocations(self, Request::new(req_v2)).await?;
        let stream = response
            .into_inner()
            .map(|item| item.and_then(transcode_message));
        Ok(Response::new(
            Box::pin(stream) as Self::WatchRevocationsStream
        ))
    }
}
