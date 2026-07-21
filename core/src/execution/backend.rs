use super::{ExecutionPolicyV1, ExecutionReceiptV1};
use crate::error::CoreResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionRequestV1 {
    pub policy: ExecutionPolicyV1,
    pub fixture_bytes: Vec<u8>,
    pub input_bytes: Vec<u8>,
}

pub trait LocalExecutionBackendV1 {
    fn backend_id(&self) -> &'static str;
    fn execute(&mut self, request: &ExecutionRequestV1) -> CoreResult<ExecutionReceiptV1>;
}
