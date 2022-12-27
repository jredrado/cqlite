use cqlite::{Error, Graph, Property,Vault};
use cqlite::{Node,Edge};

#[macro_use]
mod common;

use authcomp::Computation;
use authcomp::AuthType;
use authcomp::AuthT;
use authcomp::UnAuth;
use authcomp::Prover;

use std::fmt::Debug;

#[derive(Debug)]
pub struct SimpleVault<C>
    where C:Computation + Debug + Send + Sync + 'static
{
    _phantom: core::marker::PhantomData<C>
}

impl<C> SimpleVault<C>
    where C:Computation + Debug + Send + Sync + 'static
{
    pub fn  new() -> Self {
        SimpleVault::<C> {
            _phantom: core::marker::PhantomData::<C>::default()
        }
    }
}

impl<C> Vault for SimpleVault<C> 
    where 
        C:Computation + Debug + Send + Sync + 'static,
        C:AuthType<Node>,
        C:AuthType<Edge>
{
    type Error = Error;

    fn auth_node(&self, node: Node) -> Result<Vec<u8>, Self::Error>{
        Ok(authcomp::to_vec(&C::auth(node)))
    }

    fn unauth_node(&self,payload:&[u8]) -> Result<Node, Self::Error>{
        let node_auth_ref = authcomp::from_bytes::<AuthT<Node,C>>(payload).map_err( |_e| Error::Internal )?;
        let node_ref = node_auth_ref.unauth();

        let node = node_ref.take();

        Ok(node)
    }

    fn auth_edge(&self, edge: Edge) -> Result<Vec<u8>, Self::Error>{
        Ok(authcomp::to_vec(&C::auth(edge)))
    }

    fn unauth_edge(&self,payload:&[u8]) -> Result<Edge, Self::Error>{
        let edge_auth_ref = authcomp::from_bytes::<AuthT<Edge,C>>(payload).map_err( |_e| Error::Internal )?;
        let edge_ref = edge_auth_ref.unauth();

        let edge = edge_ref.take();

        Ok(edge)
    }

}

#[test]
fn create_and_return_with_vault() {
    let graph = Graph::open_anon().unwrap();

    let vault = SimpleVault::<Prover::<(),()>>::new();

    let graph = graph.with_vault(vault);

    let mut txn = graph.mut_txn().unwrap();
    let vals = graph
        .prepare("CREATE (a:TEST { name: 'Peter Parker', age: 42 }) RETURN a.name, a.age")
        .unwrap()
        .query_map(&mut txn, (), |m| Ok((m.get(0)?, m.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<(String, i64)>, _>>()
        .unwrap();
    assert_eq!(vals, vec![("Peter Parker".into(), 42)]);
    txn.commit().unwrap();

    let vals = graph
        .prepare("MATCH (a) RETURN a.name, a.age")
        .unwrap()
        .query_map(&mut graph.txn().unwrap(), (), |m| {
            Ok((m.get(0)?, m.get(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<(String, i64)>, _>>()
        .unwrap();
    assert_eq!(vals, vec![("Peter Parker".into(), 42)]);
}