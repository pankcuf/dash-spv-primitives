use std::collections::BTreeMap;
use std::fmt::Debug;
use std::hash::Hash;
use byte::{BytesExt, TryRead};
use diesel::{backend, deserialize, serialize, sql_types, sqlite};
use crate::consensus::Decodable;
use crate::crypto::bool::Boolean;
use crate::crypto::byte_util::AsBytes;
use crate::crypto::byte_util::{UInt128, UInt160, UInt256, UInt384, UInt512, UInt768};

#[macro_export]
macro_rules! impl_sqlite_binary_io {
    ($var_type: ident) => {
        impl serialize::ToSql<sql_types::Binary, sqlite::Sqlite> for $var_type {
            fn to_sql<W: std::io::Write>(&self, out: &mut serialize::Output<W, sqlite::Sqlite>) -> serialize::Result {
                <[u8] as serialize::ToSql<sql_types::Binary, sqlite::Sqlite>>::to_sql(self.as_bytes(), out)
            }
        }

        impl deserialize::FromSql<sql_types::Binary, sqlite::Sqlite> for $var_type {
            fn from_sql(bytes: Option<&<sqlite::Sqlite as backend::Backend>::RawValue>) -> deserialize::Result<Self> {
                let bytes_vec: Vec<u8> = <Vec<u8> as deserialize::FromSql<sql_types::Binary, sqlite::Sqlite>>::from_sql(bytes)?;
                Ok($var_type::consensus_decode(bytes_vec.as_slice())?)
            }
        }
        impl deserialize::FromSql<diesel::sql_types::Nullable<sql_types::Binary>, sqlite::Sqlite> for $var_type {
            fn from_sql(bytes: Option<&<sqlite::Sqlite as backend::Backend>::RawValue>) -> deserialize::Result<Self> {
                let bytes_vec: Vec<u8> = <Vec<u8> as deserialize::FromSql<sql_types::Binary, sqlite::Sqlite>>::from_sql(bytes)?;
                Ok($var_type::consensus_decode(bytes_vec.as_slice())?)
            }
        }
    }
}

impl_sqlite_binary_io!(UInt128);
impl_sqlite_binary_io!(UInt160);
impl_sqlite_binary_io!(UInt256);
impl_sqlite_binary_io!(UInt384);
impl_sqlite_binary_io!(UInt512);
impl_sqlite_binary_io!(UInt768);

impl serialize::ToSql<sql_types::Bool, sqlite::Sqlite> for Boolean {
    fn to_sql<W: std::io::Write>(&self, out: &mut serialize::Output<W, sqlite::Sqlite>) -> serialize::Result {
        <i32 as serialize::ToSql<sql_types::Integer, sqlite::Sqlite>>::to_sql(&(if self.0 { 1 } else { 0 }), out)
    }
}
impl deserialize::FromSql<sql_types::Nullable<sql_types::Bool>, sqlite::Sqlite> for Boolean {
    fn from_sql(value: Option<&<sqlite::Sqlite as backend::Backend>::RawValue>) -> deserialize::Result<Self> {
        Ok(Boolean(not_none!(value).read_integer() != 0))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(FromSqlRow, AsExpression)]
#[sql_type = "sql_types::Binary"]
pub struct BDictionary<'a, K: TryRead<'a, byte::ctx::Endian> + AsBytes + Ord, V: TryRead<'a, byte::ctx::Endian> + AsBytes> {
    pub map: BTreeMap<K, V>,
    _phantom: std::marker::PhantomData<&'a ()>,
}


impl<'a, K, V> BDictionary<'a, K, V>
    where
        K: Clone + Ord + TryRead<'a, byte::ctx::Endian> + AsBytes + Debug,
        V: Clone + Ord + TryRead<'a, byte::ctx::Endian> + AsBytes + Debug {
    pub fn new(map: BTreeMap<K, V>) -> BDictionary<'a, K, V> {
        BDictionary { map, _phantom: Default::default() }
    }
}

impl<'a, K, V> deserialize::FromSql<sql_types::Nullable<sql_types::Binary>, sqlite::Sqlite> for BDictionary<'a, K, V>
    where
        K: Clone + Ord + TryRead<'a, byte::ctx::Endian> + AsBytes + Debug,
        V: Clone + Ord + TryRead<'a, byte::ctx::Endian> + AsBytes + Debug {
    fn from_sql(bytes: Option<&<sqlite::Sqlite as backend::Backend>::RawValue>) -> deserialize::Result<Self> {
        let slice_ptr = <*const [u8] as deserialize:: FromSql<sql_types::Binary, sqlite::Sqlite>>::from_sql(bytes)?;
        let bytes = unsafe { &*slice_ptr };
        let offset = &mut 0;
        let mut map: BTreeMap<K, V> = BTreeMap::new();
        while offset < &mut bytes.len() {
            match bytes.read_with::<K>(offset, byte::LE) {
                Ok(key) => match bytes.read_with::<V>(offset, byte::LE) {
                    Ok(value) => { map.insert(key, value); },
                    Err(err) => { println!("Error: {:?}", err); }
                },
                Err(err) => { println!("Error: {:?}", err); },
            }
        }
        Ok(BDictionary::new(map))
    }
}

impl<'a, K, V> serialize::ToSql<sql_types::Binary, sqlite::Sqlite> for BDictionary<'a, K, V>
    where
        K: Clone + Ord + TryRead<'a, byte::ctx::Endian> + AsBytes + Debug,
        V: Clone + Ord + TryRead<'a, byte::ctx::Endian> + AsBytes + Debug {
    fn to_sql<W: std::io::Write>(&self, out: &mut serialize::Output<W, sqlite::Sqlite>) -> serialize::Result {
        for (key, value) in self.map.iter() {
            <[u8] as serialize::ToSql<sql_types::Binary, sqlite::Sqlite>>::to_sql(key.as_bytes(), out)?;
            <[u8] as serialize::ToSql<sql_types::Binary, sqlite::Sqlite>>::to_sql(value.as_bytes(), out)?;
        }
        Ok(diesel::types::IsNull::No)
    }
}

