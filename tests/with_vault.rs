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
use petgraph::graphmap::NodeTrait;

use core::num;
use std::fmt::Debug;
use std::path::{Path,PathBuf};
use std::fmt;
use std::sync::Arc;
use std::cell::RefCell;
use std::borrow::Borrow;

use serde::Serialize;
use serde::Deserialize;
use serde::Serializer;
use serde::Deserializer;
use serde::ser::SerializeStruct;

use serde::de;
use serde::de::Visitor;
use serde::de::MapAccess;
use serde::de::SeqAccess;

use collecting_hashmap::CollectingHashMap;

use minicbor::{Encode,Decode};

pub struct AuthenticatedGraph<C,MerkleStorage=MemoryDB,MerkleHasher=Blake3>
    where C:Computation + Debug 
{
    graph : Graph,
    path: PathBuf,
    _phantom: core::marker::PhantomData<C>,
    _phantom_storage: core::marker::PhantomData<MerkleStorage>,
    _phantom_merkle: core::marker::PhantomData<MerkleHasher>
}

impl<C,MerkleStorage,MerkleHasher> AuthenticatedGraph<C,MerkleStorage,MerkleHasher>
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

        AuthenticatedGraph::<C,MerkleStorage,MerkleHasher> {
            _phantom: core::marker::PhantomData::<C>::default(),
            _phantom_storage: core::marker::PhantomData::<MerkleStorage>::default(),
            _phantom_merkle: core::marker::PhantomData::<MerkleHasher>::default(),
            graph: Graph::open(path).unwrap().with_vault(Arc::new(vault)),
            path : path.to_owned()
        }

    }

    pub fn signature (&self) -> Option<Hash> {
            self.graph.vault().map( |v| v.signature()).flatten()
    }

    pub fn create_text_node<'a: 'b,'b> (&'a self, value: String) -> Result<u64,crate::Error> {

        let mut txn = self.graph.mut_txn().unwrap();
    
        let payload_bytes = to_vec(&value);

        let result : Vec<u64> = self.graph
            .prepare("CREATE (n:text { type:'text', payload:$payload }) RETURN ID(n)")?
            .query_map(&mut txn, (("payload", payload_bytes),), |m| {
                Ok(m.get(0)?)
            })?
            .collect::<Result<Vec<_>, _>>()?;
    
        txn.commit()?;
    
        result.get(0).copied().ok_or(crate::Error::Internal)
    }
    
    pub fn create_element_node<'a: 'b,'b,P:Encode + Decode<'a>> (&'a self, tag: &str,children:&Vec<u64>,properties:&Vec<(String,String)>,root: bool, payload: P ) -> Result<u64,crate::Error> {
    
        let mut txn = self.graph.mut_txn().unwrap();
    
        let mut string_properties = properties.iter().map ( |(key,value)| format!(" {}:'{}'",key,value)).collect::<Vec<_>>().join(",");

        if !string_properties.is_empty() {
            string_properties.insert_str(0,", ");
        }

        let root_string = if root { "TRUE" } else { "FALSE" };

        let query_string = format!("CREATE (n:element {{ type:'element', root: {} , tag:$tag , payload:$payload {} }}) RETURN ID(n)",root_string,string_properties);

        println!("{}",&query_string);

        let payload_bytes = to_vec(&payload);

        let result : Vec<u64> = self.graph
            .prepare(&query_string)?
            .query_map(&mut txn, (("tag", tag),("payload",payload_bytes),), |m| {
                Ok(m.get(0)?)
            })?
            .collect::<Result<Vec<_>, _>>()?;
    
        let element_id = result.get(0).ok_or(crate::Error::Internal)?;
    
        if !children.is_empty() {
                //not id in ()
                let mut where_string = String::from("where ");
                let mut child_iter = children.iter();
    
                //First element
                if let Some(child_id) = child_iter.next() {
                    where_string.push_str( &format!("ID(c) = {}",child_id));
                }
    
                //Rest ot elements
                for child_id in child_iter {
                    where_string.push_str( &format!(" or ID(c) = {}",child_id));
                }
    
                where_string.push_str(&format!(" and ID(n) = {}",element_id));
    
                let query_string = format!("MATCH (c) MATCH (n) {} CREATE (n) -[:CHILD]-> (c) RETURN ID(n),ID(c)", where_string);
        
                println!("{}",query_string);
    
                let result : Vec<(u64,u64)> = self.graph
                    .prepare(&query_string)?
                    .query_map(&mut txn, (("tag", tag),), |m| {
                        Ok((m.get(0)?,m.get(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                
                println!("{:?}",result);
        }
    
        txn.commit()?;
    
        Ok(*element_id)
    
    }
    
}


impl<C,MerkleStorage,MerkleHasher> Default for AuthenticatedGraph<C,MerkleStorage,MerkleHasher> 
    where 
        C:Computation + Debug + 'static, 
        C:AuthType<Node>,
        C:AuthType<Edge>
{
    fn default() -> Self{

        let vault = SimpleVault::<C>::default();

        AuthenticatedGraph::<C,MerkleStorage,MerkleHasher> {
            _phantom: core::marker::PhantomData::<C>::default(),
            _phantom_storage: core::marker::PhantomData::<MerkleStorage>::default(),
            _phantom_merkle: core::marker::PhantomData::<MerkleHasher>::default(),
            graph: Graph::open_anon().unwrap().with_vault(Arc::new(vault)),
            path: PathBuf::default()
        }

    }
}


//The shallow projection of Authenticated storage is the root of the merkle tree (Vault )
// and the paths of the graph and the merkletree

const SERIALIZER_NAME :&str = "AuthenticatedGraph";

impl<C,MerkleStorage,MerkleHasher> Serialize for  AuthenticatedGraph<C,MerkleStorage,MerkleHasher>
    where
        C:Computation + Debug + 'static,
        MerkleHasher: monotree::Hasher + 'static,
        MerkleStorage: monotree::Database + 'static,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {

        let mut state = serializer.serialize_struct(SERIALIZER_NAME, 2)?;
        state.serialize_field("signature", &self.signature())?;
        state.serialize_field("path", &self.path)?;    
        state.end()

    }
}

impl<'de,C,MerkleStorage,MerkleHasher>  Deserialize<'de> for AuthenticatedGraph<C,MerkleStorage,MerkleHasher> 
    where
        C:Computation + Debug + 'static,
        MerkleHasher: monotree::Hasher + 'static,
        MerkleStorage: monotree::Database + 'static,
        C:AuthType<Node>,
        C:AuthType<Edge>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Signature, Path }

        // This part could also be generated independently by:
        //
        //    #[derive(Deserialize)]
        //    #[serde(field_identifier, rename_all = "lowercase")]
        //    enum Field { Secs, Nanos }
        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`signature` or `path`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "signature" => Ok(Field::Signature),
                            "path" => Ok(Field::Path),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }


        struct AuthenticatedGraphVisitor<C,MerkleStorage,MerkleHasher>{
            _phantom: core::marker::PhantomData<C>,
            _phantom_storage: core::marker::PhantomData<MerkleStorage>,
            _phantom_merkle: core::marker::PhantomData<MerkleHasher>
        }


        impl<'de,C,MerkleStorage,MerkleHasher>  Visitor<'de> for AuthenticatedGraphVisitor<C,MerkleStorage,MerkleHasher> 
                where
                        C:Computation + Debug + 'static,
                        MerkleHasher: monotree::Hasher + 'static,
                        MerkleStorage: monotree::Database + 'static,
                        C:AuthType<Node>,
                        C:AuthType<Edge>
        {
            type Value = AuthenticatedGraph::<C,MerkleStorage,MerkleHasher> ;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct AuthenticatedGraph")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<AuthenticatedGraph::<C,MerkleStorage,MerkleHasher>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let signature = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let path = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let tree = AuthenticatedGraph::<C,MerkleStorage,MerkleHasher>::new(path);
                Ok(tree)
            }

            fn visit_map<V>(self, mut map: V) -> Result<AuthenticatedGraph::<C,MerkleStorage,MerkleHasher> , V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut signature = None;
                let mut path = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }                       
                    }
                }

                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;
                let path = path.ok_or_else(|| de::Error::missing_field("path"))?;

                let tree = AuthenticatedGraph::<C,MerkleStorage,MerkleHasher>::new(path);
                Ok(tree)
            }
        }

        const FIELDS: &'static [&'static str] = &["signature", "path"];
        deserializer.deserialize_struct(SERIALIZER_NAME, FIELDS,  AuthenticatedGraphVisitor::<C,MerkleStorage,MerkleHasher>{
                _phantom: core::marker::PhantomData::<C>::default(),
                _phantom_storage: core::marker::PhantomData::<MerkleStorage>::default(),
                _phantom_merkle: core::marker::PhantomData::<MerkleHasher>::default(),
        })
    }
}


impl<C,MerkleStorage,MerkleHasher> core::fmt::Debug for AuthenticatedGraph<C,MerkleStorage,MerkleHasher>  
    where
        C:Computation + Debug + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedGraph")
         .field("path", &self.path)
         .finish()
    }
}

impl<C,MerkleStorage,MerkleHasher> Clone for AuthenticatedGraph<C,MerkleStorage,MerkleHasher>    
    where
        C:Computation + Debug + 'static,
        MerkleHasher: monotree::Hasher + 'static,
        MerkleStorage: monotree::Database + 'static,
        C:AuthType<Node>,
        C:AuthType<Edge>
{
    fn clone(&self) -> Self {
        AuthenticatedGraph::<C,MerkleStorage,MerkleHasher>::new(&self.path)
    }
}


impl<C,MerkleStorage,MerkleHasher> PartialEq for AuthenticatedGraph<C,MerkleStorage,MerkleHasher>  
    where
        C:Computation + Debug + 'static,
        MerkleHasher: monotree::Hasher + 'static,
        MerkleStorage: monotree::Database + 'static,

{
    fn eq(&self, other: &Self) -> bool{
        self.signature() == other.signature()
    }
}  

impl<C,MerkleStorage,MerkleHasher> authcomp::ToJSON for AuthenticatedGraph<C,MerkleStorage,MerkleHasher>  
    where   
        C:Computation + Debug
{

    fn ser_json (&self, d: usize, s: &mut authcomp::JSONState) {
        todo!()
    }
}

impl<C,MerkleStorage,MerkleHasher> minicbor::Encode for AuthenticatedGraph<C,MerkleStorage,MerkleHasher>      
    where
        C:Computation + Debug + 'static,
{
    fn encode<W: minicbor::encode::Write>(&self, e: &mut minicbor::Encoder<W>) -> Result<(), minicbor::encode::Error<W::Error>> {
        todo!()
    }
}


impl<'b, C,MerkleStorage,MerkleHasher> minicbor::Decode<'b> for AuthenticatedGraph<C,MerkleStorage,MerkleHasher>     
    where
        C:Computation + Debug + 'static,
{
    fn decode(d: &mut minicbor::decode::Decoder<'b>) -> Result<Self, minicbor::decode::Error> {
        todo!()
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


use petgraph::prelude::*;

#[derive(Debug)]
struct MemoryGraph<N: std::hash::Hash + std::cmp::Eq ,E>{
    graph : DiGraphMap<N,E>,
    payloads : std::collections::HashMap<N,Vec<u8>>
}



impl<N,E> MemoryGraph<N,E> 
    where   
        N: NodeTrait
{
    fn new() -> Self {
        MemoryGraph::<N,E> {
            graph: DiGraphMap::<N,E>::new(),
            payloads: std::collections::HashMap::<N,Vec<u8>>::new()
        }
    }

}

impl std::iter::FromIterator<(u64,u64)> for MemoryGraph<u64,()>

{
    fn from_iter<I: IntoIterator<Item=(u64,u64)>>(iter: I) -> Self {

        MemoryGraph::<u64,()> {
            graph: DiGraphMap::<_,()>::from_edges(iter),
            payloads: std::collections::HashMap::<u64,Vec<u8>>::new()
        }
    }
}


impl<'a> std::iter::FromIterator<(u64,Vec<u8>,u64,Vec<u8>)> for MemoryGraph<u64,()>

{
    fn from_iter<I: IntoIterator<Item=(u64,Vec<u8>,u64,Vec<u8>)>>(iter: I) -> Self {
       
        let mut payloads = std::collections::HashMap::<u64,Vec<u8>>::new();

        let graph = DiGraphMap::<_,()>::from_edges(
                            iter.into_iter()
                            .map( |(n_id,n_payload,t_id,t_payload)|{ 
                                payloads.insert(n_id,n_payload);
                                payloads.insert(t_id,t_payload);
                                (n_id,t_id) 
                            }));

        MemoryGraph::<u64,()> {
                graph,
                payloads
        }
        
    }
}

pub fn to_vec <A> (value: &A) -> Vec<u8>
        where A: Encode                
{
        
        use minicbor::Encoder;

        let mut e = Encoder::new(Vec::new());
        value.encode(&mut e);

        e.into_inner()

                
}

pub fn from_bytes<'a,A: Decode<'a>> (value: &'a[u8]) -> Result<A,minicbor::decode::Error> {

        minicbor::decode(value)
        //.map_err(|e| error::Error::Shallow(String::from(format!("{:?}",e))))
        
}

//cargo test -- --test-threads=1 --nocapture
//Globals is not thread safe

#[test]
fn create_and_return_with_vault() {

    let comp = Prover::<(),()>::run (|| {

        //let graph = Graph::open("vault.graph").unwrap();


        let vault = AuthenticatedGraph::<Prover::<(),()>>::default();

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


fn get_blob<'a> (p: &'a Property) -> Result<&'a [u8],cqlite::Error> {
    match p {
        Property::Blob(b) => Ok(b.as_slice()),
        _ => Err(cqlite::Error::Internal)
    }
}

#[test]
fn match_multiple_edges_with_vault() {

    let comp = Prover::<(),()>::run (|| {

        //let graph = Graph::open("vault_multiple.graph").unwrap();


        //let vault_auth = Prover::<(),()>::auth(AuthenticatedGraph::<Prover::<(),()>,Sled,Blake3>::new(Path::new("/tmp/vault_multiple.graph")));
        //let vault_unauth_ref = vault_auth.unauth();
        //let vault : &AuthenticatedGraph::<Prover::<(),()>,Sled,Blake3> =  &(*vault_unauth_ref).borrow();

        let vault = AuthenticatedGraph::<Prover::<(),()>,Sled,Blake3>::new(Path::new("/tmp/vault_multiple3.graph"));

        let node_id_1 = vault.create_text_node(String::from("text1")).map_err( |_e| ())?;
        let node_id_2 = vault.create_text_node(String::from("text2")).map_err( |_e| ())?;

        let node_id_3 = vault.create_text_node(String::from("text3")).map_err( |_e| ())?;     
        let mut children = Vec::<u64>::new();
        children.push(node_id_3);

        let node_id_4 = vault.create_element_node("p",&children,&Vec::new(),false,"dadfd").map_err( |_e| ())?;

        let mut children = Vec::<u64>::new();
        children.push(node_id_1);
        children.push(node_id_2);
        children.push(node_id_4);

        println!("Result {:?} {:?}",node_id_1,node_id_2);

        let mut properties = Vec::<(String,String)>::new();
        properties.push(("prop1".to_string(),"esto es una prueba".to_string()));
        properties.push(("prop2".to_string(),"5".to_string()));

        let root = vault.create_element_node("title",&children,&properties,true,"ddkdkdldl").map_err( |_e| ())?;


        println!("Root {:?}",root);

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
        let mut pairs: CollectingHashMap<u64, u64> = vault.graph
            .prepare("MATCH (a) -[e:CHILD]-> (b) RETURN ID(a), ID(b)")
            .unwrap()
            .query_map(&mut vault.graph.txn().unwrap(), (), |m| {
                Ok((m.get(0)?, m.get(1)?))
            })
            .unwrap()
            .collect::<Result<CollectingHashMap<_,_>, _>>()
            .unwrap();
        */

        let gr: Vec<(u64,Vec<u8>,u64,Vec<u8>)>= vault.graph
            .prepare("MATCH (a) -[e:CHILD]-> (b) RETURN ID(a), a.payload, ID(b), b.payload")
            .unwrap()
            .query_map(&mut vault.graph.txn().unwrap(), (), |m| {
                Ok((m.get(0)?, m.get(1)?,m.get(2)?,m.get(3)?))
            })
            .unwrap()
            .collect::<Result<Vec<(_,_,_,_)>, _>>()
            .unwrap();

        println!("Edges {:?}", gr);

        let gr: MemoryGraph<u64,()> = vault.graph
            .prepare("MATCH (a) -[e:CHILD]-> (b) RETURN ID(a), a.payload, ID(b), b.payload")
            .unwrap()
            .query_map(&mut vault.graph.txn().unwrap(), (), |m| {
                Ok((m.get(0)?, m.get(1)?,m.get(2)?,m.get(3)?))
            })
            .unwrap()
            .collect::<Result<MemoryGraph<_,_>, _>>()
            .unwrap();


        println!("MemoryGraph {:?}", gr);
        
         
        println!("DFS: ");
        let mut dfs = Dfs::new(&gr.graph, root);
        while let Some(node) = dfs.next(&gr.graph) {
            print!(" {:?}",node)
        }

        println!("\nBFS: ");
        let mut bfs = Bfs::new(&gr.graph, root);
        while let Some(node) = bfs.next(&gr.graph) {
            print!(" {:?}",node)
        }
        

        let vault_auth = Prover::<(),()>::auth(vault);
        println!("Structure signature: {:?}",Prover::<(),()>::signature(&vault_auth));

        Ok(())
    });

    println!("Computation: {:?}",comp.get());
    println!("Computation Proofs Length: {:?}",comp.get_proofs());
    
}