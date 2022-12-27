

use crate::store::types::{Node,Edge};

pub trait SendSyncError: std::error::Error + Send + Sync + 'static {}
impl<T> SendSyncError for T where T: std::error::Error + Send + Sync + 'static {}

/// A provider of encryption for blocks of data.
pub trait Vault: std::fmt::Debug + Send + Sync + 'static {
    /// The error type that the vault can produce.
    type Error: SendSyncError;

    fn auth_node(&self, node: Node) -> Result<Vec<u8>, Self::Error>;
    fn unauth_node(&self,payload:&[u8]) -> Result<Node, Self::Error>;

    fn auth_edge(&self, edge: Edge) -> Result<Vec<u8>, Self::Error>;
    fn unauth_edge(&self,payload:&[u8]) -> Result<Edge, Self::Error>;

}