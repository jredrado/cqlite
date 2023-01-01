use cqlite::{Error, Graph, Property,Vault, Txn};
use cqlite::{Node,Edge};

#[macro_use]
mod common;

use authcomp::Computation;
use authcomp::AuthType;
use authcomp::AuthT;
use authcomp::UnAuth;
use authcomp::Prover;

use monotree::Monotree;
use monotree::database::sled::Sled;
use monotree::database::MemoryDB;

use monotree::hasher::{Blake2b,Blake3};
use monotree::Hash;
use monotree::Hasher;

use std::fmt::Debug;
use std::path::Path;
use std::fmt;
use std::sync::Arc;
use std::cell::RefCell;
use std::borrow::Borrow;

pub struct AuthenticatedStore<C,MerkleStorage=MemoryDB,MerkleHasher=Blake3>
    where C:Computation + Debug 
{
    graph : Graph,
    _phantom: core::marker::PhantomData<C>,
    _phantom_storage: core::marker::PhantomData<MerkleStorage>,
    _phantom_merkle: core::marker::PhantomData<MerkleHasher>
}

impl<C,MerkleStorage,MerkleHasher> AuthenticatedStore<C,MerkleStorage,MerkleHasher>
    where 
        C:Computation + Debug + 'static,
        MerkleHasher: monotree::Hasher + 'static,
        MerkleStorage: monotree::Database + 'static
{
    
    pub fn  new(path: &Path) -> Self 
        where 
            C:AuthType<Node>,
            C:AuthType<Edge>
    {
        let merkle_path = path.with_extension("merkle");
        let vault = SimpleVault::<C,MerkleStorage,MerkleHasher>::new(&merkle_path);

        AuthenticatedStore::<C,MerkleStorage,MerkleHasher> {
            _phantom: core::marker::PhantomData::<C>::default(),
            _phantom_storage: core::marker::PhantomData::<MerkleStorage>::default(),
            _phantom_merkle: core::marker::PhantomData::<MerkleHasher>::default(),
            graph: Graph::open(path).unwrap().with_vault(Arc::new(vault)),
        }

    }

    pub fn signature (&self) -> Option<Hash> {
            self.graph.vault().map( |v| v.signature()).flatten()
    }
}


impl<C,MerkleStorage,MerkleHasher> Default for AuthenticatedStore<C,MerkleStorage,MerkleHasher> 
    where 
        C:Computation + Debug + 'static, 
        C:AuthType<Node>,
        C:AuthType<Edge>
{
    fn default() -> Self{

        let vault = SimpleVault::<C>::default();

        AuthenticatedStore::<C,MerkleStorage,MerkleHasher> {
            _phantom: core::marker::PhantomData::<C>::default(),
            _phantom_storage: core::marker::PhantomData::<MerkleStorage>::default(),
            _phantom_merkle: core::marker::PhantomData::<MerkleHasher>::default(),
            graph: Graph::open_anon().unwrap().with_vault(Arc::new(vault)),
        }

    }
}

pub struct SimpleVault<C,MerkleStorage=MemoryDB,MerkleHasher=Blake3>
    where 
        C:Computation + Debug  
{
    _phantom: core::marker::PhantomData<C>,
    merkle_tree : Option<RefCell<monotree::Monotree<MerkleStorage,MerkleHasher>>>,
    root: RefCell<Option<Hash>>,
}

impl<C,MerkleStorage,MerkleHasher> SimpleVault<C,MerkleStorage,MerkleHasher>
    where 
        C:Computation + Debug,
        MerkleStorage : monotree::Database,
        MerkleHasher : monotree::Hasher
{
    pub fn  new(path: &Path) -> Self 
    {

        SimpleVault::<C,MerkleStorage,MerkleHasher> {
            _phantom: core::marker::PhantomData::<C>::default(),
            merkle_tree: path.to_str().map(|p| RefCell::new(Monotree::<MerkleStorage,MerkleHasher>::new(p))),
            root: RefCell::new(None),
        }

    }
}

impl<C> Default for SimpleVault<C> 
    where 
        C:Computation + Debug
{
    fn default() -> Self{
        SimpleVault::<C> {
            _phantom: core::marker::PhantomData::<C>::default(),
            merkle_tree: Some(RefCell::new(Monotree::default())),
            root: RefCell::new(None),
        }
    }
}

impl<C,MerkleStorage,MerkleHasher> Debug for SimpleVault<C,MerkleStorage,MerkleHasher> 
    where C:Computation + Debug 
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SimpleVault")
    }
}

impl<C,MerkleStorage,MerkleHasher> Vault for SimpleVault<C,MerkleStorage,MerkleHasher> 
    where 
        C:Computation + Debug ,
        C:AuthType<Node>,
        C:AuthType<Edge>,
        MerkleHasher : monotree::Hasher,
        MerkleStorage : monotree::Database
{
    type Error = Error;

    fn signature(&self) -> Option<Hash> {
        *self.root.borrow()
    }

    fn auth_node(&self, node: Node) -> Result<Vec<u8>, Self::Error>{

        let hasher = MerkleHasher::new();

        let persisted_node = authcomp::to_vec(&C::auth(node));
        let key_kv = hasher.digest(&persisted_node);

        let new_root = match *self.root.borrow() {
            Some(old_root) => self.merkle_tree.as_ref().and_then ( |t| t.borrow_mut().insert(Some(&*old_root.borrow()), &key_kv, &key_kv).ok()?),
            None => self.merkle_tree.as_ref().and_then ( |t| t.borrow_mut().insert(None, &key_kv, &key_kv).ok()?)
        };

        self.root.replace(new_root);
       
        Ok(persisted_node)
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

//cargo test -- --test-threads=1 --nocapture
//Globals is not thread safe

#[test]
fn create_and_return_with_vault() {

    let comp = Prover::<(),()>::run (|| {

        //let graph = Graph::open("vault.graph").unwrap();


        let vault = AuthenticatedStore::<Prover::<(),()>>::default();

        let mut txn = vault.graph.mut_txn().unwrap();
        let vals = vault.graph
            .prepare("CREATE (a:TEST { name: 'Peter Parker', age: 42 }) RETURN a.name, a.age")
            .unwrap()
            .query_map(&mut txn, (), |m| Ok((m.get(0)?, m.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<(String, i64)>, _>>()
            .unwrap();
        assert_eq!(vals, vec![("Peter Parker".into(), 42)]);
        txn.commit().unwrap();

        let mut txn = vault.graph.txn().unwrap();

        let st = vault.graph
            .prepare("MATCH (a) RETURN a.name, a.age")
            .unwrap();

        let mq = st
            .query_map(&mut txn, (), |m| {
                Ok((m.get(0)?, m.get(1)?))
            })
            .unwrap();

        let vals = mq.collect::<Result<Vec<(String, i64)>, _>>();
        println!("{:?}",vals);
        
        assert_eq!(vals.unwrap(), vec![("Peter Parker".into(), 42)]);

        println!("Signature {:?}",vault.signature());

        Ok(())
    });

    println!("Computation: {:?}",comp.get());
    println!("Computation Proofs Length: {:?}",comp.get_proofs());

}


type NODE_ID = u64;

fn create_text_node<'a: 'b,'b> (graph: &'a Graph, value: &str) -> Result<NODE_ID,crate::Error> {

    let mut txn = graph.mut_txn().unwrap();

    let result : Vec<u64> = graph
        .prepare("CREATE (n:text { type:'text', value:$value }) RETURN ID(n)")?
        .query_map(&mut txn, (("value", value),), |m| {
            Ok(m.get(0)?)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    txn.commit()?;

    result.get(0).copied().ok_or(crate::Error::Internal)
}

fn create_element_node<'a: 'b,'b> (graph: &'a Graph, tag: &str,children:&Vec<NODE_ID>) -> Result<NODE_ID,crate::Error> {

    let mut txn = graph.mut_txn().unwrap();

    let result : Vec<u64> = graph
        .prepare("CREATE (n:element { type:'element', tag:$tag }) RETURN ID(n)")?
        .query_map(&mut txn, (("tag", tag),), |m| {
            Ok(m.get(0)?)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    txn.commit()?;

    result.get(0).copied().ok_or(crate::Error::Internal)
}


#[test]
fn match_multiple_edges_with_vault() {

    let comp = Prover::<(),()>::run (|| {

        //let graph = Graph::open("vault_multiple.graph").unwrap();


        let vault = AuthenticatedStore::<Prover::<(),()>,Sled,Blake3>::new(Path::new("/tmp/vault_multiple.graph"));


        let result = create_text_node(&vault.graph,"dadadfd");


        println!("Result {:?}",result);

        let result = create_element_node(&vault.graph,"title",&Vec::new());


        println!("Result {:?}",result);

        println!("Signature {:?}",vault.signature());

        /* 
        let result : Vec<u64> = graph
            .prepare("CREATE (n:title) RETURN ID(n)")
            .unwrap()
            .query_map(&mut txn, (), |m| {
                Ok(m.get(0)?)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
        .unwrap();

        println!("Result {:?}",result);

        txn.commit().unwrap();
        */

        /* 
        let mut pairs: Vec<(u64, u64)> = graph
            .prepare("MATCH (a) -> (b) RETURN ID(a), ID(b)")
            .unwrap()
            .query_map(&mut graph.txn().unwrap(), (), |m| {
                Ok((m.get(0)?, m.get(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        pairs.sort_unstable();

        assert_eq!(pairs, [(0, 1), (0, 2)]);
        */

        Ok(())
    });

    println!("Computation: {:?}",comp.get());
    println!("Computation Proofs Length: {:?}",comp.get_proofs());
    
}