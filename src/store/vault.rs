

use crate::store::types::{Node,Edge};

use std::fmt::Debug;

use serde::{Serialize,de::DeserializeOwned};
use minicbor::{Encode,Decode};
use nanoserde::SerJson as ToJSON;

pub trait DecodeOwned: for<'de> Decode<'de> {}
impl<T> DecodeOwned for T where T: for<'de> Decode<'de> {}

pub trait SendSyncError: std::error::Error + Send + Sync + 'static {}
impl<T> SendSyncError for T where T: std::error::Error + Send + Sync + 'static {}

trait Req : Default + Debug +  Clone + PartialEq + Serialize + DeserializeOwned + ToJSON + Encode + DecodeOwned {}

/// A provider of encryption for blocks of data.
pub trait Vault: std::fmt::Debug + Send + Sync + 'static 
{
    /// The error type that the vault can produce.
    type Error: SendSyncError;
   
    fn auth_node(&self, node: Node) -> Result<Vec<u8>, Self::Error>;
    fn unauth_node(&self,payload:&[u8]) -> Result<Node, Self::Error>;

    fn auth_edge(&self, edge: Edge) -> Result<Vec<u8>, Self::Error>;
    fn unauth_edge(&self,payload:&[u8]) -> Result<Edge, Self::Error>;

}