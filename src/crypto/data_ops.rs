use std::collections::HashSet;
use std::fmt::Write;
use byte::BytesExt;
use hashes::Hash;
use crate::crypto::byte_util::{AsBytes, BytesDecodable};
use crate::crypto::UInt256;
use crate::util::base58;
use crate::util::base58::encode_slice;

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
    fn to_sha256(&self) -> UInt256;
    fn to_sha256d(&self) -> UInt256;
}

impl Data for [u8] {

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, byte::LE) {
            Ok(bits) => (bits >> bit_position) & 1 != 0,
            _ => false
        }
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for mut i in 0..self.len() {
            let mut bits: u8 = self.read_with(&mut i, byte::LE).unwrap();
            for _j in 0..8 {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            }
        }
        count
    }

    fn to_sha256(&self) -> UInt256 {
        UInt256(hashes::sha256::Hash::hash(self).into_inner())
    }
    fn to_sha256d(&self) -> UInt256 {
        UInt256(hashes::sha256d::Hash::hash(self).into_inner())
    }
}


pub fn hex_with_data(data: &[u8]) -> String {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let mut iter = data.iter();
    while let Some(a) = iter.next() {
        write!(s, "{:02x}", a).unwrap();
    }
    s
}


pub fn short_hex_string_from(data: &[u8]) -> String {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        hex_data[..7].to_string()
    } else {
        hex_data
    }
}


/// Extracts the common values in `a` and `b` into a new set.
pub fn inplace_intersection<T>(a: &mut HashSet<T>, b: &mut HashSet<T>) -> HashSet<T>
    where
        T: std::hash::Hash,
        T: Eq,
{
    let x: HashSet<(T, bool)> = a
        .drain()
        .map(|v| {
            let intersects = b.contains(&v);
            (v, intersects)
        })
        .collect();
    let mut c = HashSet::new();
    for (v, is_inter) in x {
        if is_inter {
            c.insert(v);
        } else {
            a.insert(v);
        }
    }
    b.retain(|v| !c.contains(&v));
    c
}


/*pub fn script_elements(script: &[u8]) -> &[u8] {
    // NSMutableArray *a = [NSMutableArray array];
    let mut a = [0u8];

    //const uint8_t *b = (const uint8_t *)self.bytes;
    let mut l = 0;
    let length = script.len();

    for mut i in 0..length {
        if script[i] > OP_PUSHDATA4.into_u8() {
            l = 1;
            a.push(b[i]);
        }
        match b[i] {
            0 => {
                l = 1;
                a.push(0);
                continue;
            },
            OP_PUSHDATA1 => {
                i += 1;
                if i + 1 > length { return &a; }
                l = b[i];
                i += 1;
                break;
            },
            OP_PUSHDATA2 => {
                i += 1;
                if i + 2 > length { return &a; }
                l = b[i];
                i += 2;
                break;
            },
            OP_PUSHDATA4 => {
                i += 1;
                if i + 4 > length { return &a; }
                l = b[i];
                i += 4;
                break;
            }
            _ => {
                l = b[i];
                i += 1;
                break;
            }
        }
        if i + l > length { return &a; }
        [a addObject:[NSData dataWithBytes:&b[i] length:l]];
    }
    return &a;
}

pub fn address_with_script_pub_key(script: &[u8], pub_key_address: u8, script_address: i32) -> &str {
    let elem = script_elements(script);
    let l = elem.len();
    let mut d: Vec<u8> = Vec::new();

    if l == 5 &&
        elem[0] == OP_DUP &&
        elem[1] == OP_HASH160 &&
        elem[2] == 20 &&
        elem[3] == OP_EQUALVERIFY &&
        elem[4] == OP_CHECKSIG {
        // pay-to-pubkey-hash scriptPubKey
        d.push(pub_key_address);
        d.push(20);
    } else if l == 3 &&
        elem[0] == OP_HASH160 &&
        elem[1] == 20 &&
        elem[2] == OP_EQUAL {
        // pay-to-script-hash scriptPubKey
        d.push(script_address as u8);
        d.push(20);
    } else if l == 2 &&
        elem[0] == 65 ||
        elem[0] == 33 &&
        elem[1] == OP_CHECKSIG {
        // pay-to-pubkey scriptPubKey
        d.push(pub_key_address);
        d.push(elem[0].hash)
    } else {
        // unknown script type
        //return None;
    }
    d.base_58_check()
}

pub fn address_with_script_signature(signature: &[u8], pub_key_address: u8, script_address: i32) -> &str {
    let elem = script_elements(script);
    let l = elem.len();
    let mut d: Vec<u8> = Vec::new();
    if l >= 2 &&
        elem[l - 2] <= OP_PUSHDATA4.into_u8() &&
        elem[l - 2] > 0 &&
        (elem[l - 1] == 65 ||
        elem[l - 1] == 33) {
        // pay-to-pubkey-hash scriptSig
        d.push(pub_key_address);
        d.push(elem[l - 1].has);
        hash160::Hash::hash(&self.key.serialize())
    } else if l >= 2 &&
        elem[l - 2] <= OP_PUSHDATA4.into_u8() &&
        elem[l - 2] > 0 &&
        elem[l - 1] <= OP_PUSHDATA4.into_u8() &&
        elem[l - 1] > 0 {
        d.push(script_address as u8)
        //[d appendBytes:[elem[l - 1] hash160].u8 length:sizeof(UInt160)];

    } else if l >= 1 && elem[l - 1] <= OP_PUSHDATA4.into_u8() && elem[l - 1] > 0 {
        // pay-to-pubkey scriptSig
        d.push(pub_key_address);
        //        DSKey * key = [DSKey keyRecoveredFromCompactSig:elem[l - 1] andMessageDigest:transactionHash];
        //        [d appendBytes:[key.publicKey hash160].u8 length:sizeof(UInt160)];
        //TODO: implement Peter Wullie's pubKey recovery from signature
        //return None;
    }

    else {
        // unknown script type
        //return None;
    }
    d.base_58_check()
}*/

#[cfg(useDarkCoinSeed)]
pub mod bip32 {
    pub const SEED_KEY: &'static str = "Darkcoin seed";
    pub const XPRV_MAINNET: &'static [u8] = b"\x02\xFE\x52\xCC";
    pub const XPRV_TESTNET: &'static [u8] = b"\x02\xFE\x52\xCC";
    pub const XPUB_MAINNET: &'static [u8] = b"\x02\xFE\x52\xF8";
    pub const XPUB_TESTNET: &'static [u8] = b"\x02\xFE\x52\xF8";
    pub const HARD: u32 = 0x80000000;
    pub const HARD_LE: u32 = 0x00000080;
}

#[cfg(not(useDarkCoinSeed))]
pub mod bip32 {
    pub const SEED_KEY: &'static str = "Bitcoin seed";
    pub const XPRV_MAINNET: &'static [u8] = b"\x04\x88\xAD\xE4";
    pub const XPRV_TESTNET: &'static [u8] = b"\x04\x35\x83\x94";
    pub const XPUB_MAINNET: &'static [u8] = b"\x04\x88\xB2\x1E";
    pub const XPUB_TESTNET: &'static [u8] = b"\x04\x35\x87\xCF";
    pub const HARD: u32 = 0x80000000;
    pub const HARD_LE: u32 = 0x00000080;
}

#[cfg(not(useDarkCoinSeed))]
pub mod dip14 {
    pub const DPTS_TESTNET: &'static [u8] = b"\x0E\xED\x27\x74";
    pub const DPTP_TESTNET: &'static [u8] = b"\x0E\xED\x27\x0B";
    pub const DPMS_MAINNET: &'static [u8] = b"\x0E\xEC\xF0\x2E";
    pub const DPMP_MAINNET: &'static [u8] = b"\x0E\xEC\xEF\xC5";
}
pub fn uint256_from_u32(value: u32) -> UInt256 {
    let offset = &mut 0;
    let mut vec8: Vec<u8> = vec![];
    vec8.write_with::<u32>(offset, value, byte::LE).unwrap();
    vec8.write_with::<u32>(offset, 0, byte::LE).unwrap();
    vec8.write_with::<u64>(offset, 0, byte::LE).unwrap();
    vec8.write_with::<u64>(offset, 0, byte::LE).unwrap();
    vec8.write_with::<u64>(offset, 0, byte::LE).unwrap();
    UInt256::from_bytes(vec8.as_slice(), &mut 0).unwrap()
}
pub fn uint256_from_long(value: u64) -> UInt256 {
    let offset = &mut 0;
    let mut vec8: Vec<u8> = vec![];
    vec8.write_with::<u64>(offset, value, byte::LE).unwrap();
    vec8.write_with::<u64>(offset, 0, byte::LE).unwrap();
    vec8.write_with::<u64>(offset, 0, byte::LE).unwrap();
    vec8.write_with::<u64>(offset, 0, byte::LE).unwrap();
    UInt256::from_bytes(vec8.as_slice(), &mut 0).unwrap()
}

pub fn uint256_is_31_bits(value: UInt256) -> bool {
    let u64_1 = value.0.read_with::<u64>(&mut 64, byte::LE).unwrap();
    let u64_2 = value.0.read_with::<u64>(&mut 128, byte::LE).unwrap();
    let u64_3 = value.0.read_with::<u64>(&mut 192, byte::LE).unwrap();
    let u32_0 = value.0.read_with::<u32>(&mut 0, byte::LE).unwrap();
    let u32_1 = value.0.read_with::<u32>(&mut 32, byte::LE).unwrap();
    ((u64_1 | u64_2 | u64_3) == 0) && (u32_1 == 0) && (u32_0 & 0x80000000) == 0
}

/// helper function for serializing BIP32 master public/private keys to standard export format
pub unsafe fn deserialize<'a>(
    string: &'a str,
    depth: *mut u8,
    fingerprint: *mut u32,
    hardened: *mut bool,
    child: *mut UInt256,
    chain_hash: *mut UInt256,
    key: *mut Vec<u8>,
    mainnet: bool) -> bool {
    match base58::from(string) {
        Ok(data) => match data.len() {
            82 => {
                let child32 = &mut 0;
                let is_deserialized = deserialize32(string, depth, fingerprint, child32, chain_hash, key, mainnet);
                if !is_deserialized {
                    return false;
                }
                *child32 = (*child32).reverse_bits();
                *hardened = (*child32 & bip32::HARD) > 0;
                *child = uint256_from_u32(*child32 & !bip32::HARD);
                is_deserialized
            },
            111 => {
                deserialize256(string, depth, fingerprint, hardened, child, chain_hash, key, mainnet)
            },
            _ => false
        },
        _ => false
    }
}

/// helper function for serializing BIP32 master public/private keys to standard export format
pub fn serialize(depth: u8, fingerprint: u32, hardened: bool, child: UInt256, chain: UInt256, key: &[u8], mainnet: bool) -> String {
    if uint256_is_31_bits(child) {
        let mut small_i = child.0.read_with::<u32>(&mut 0, byte::LE).unwrap();
        if hardened {
            small_i |= bip32::HARD;
        }
        small_i = small_i.reverse_bits();
        serialize32(depth, fingerprint, small_i, chain, key, mainnet)
    } else {
        serialize256(depth, fingerprint, hardened, child, chain, key, mainnet)
    }
}


/// helper function for serializing BIP32 master public/private keys to standard export format
pub unsafe fn deserialize32<'a>(
    string: &'a str,
    depth: *mut u8,
    fingerprint: *mut u32,
    child: *mut u32,
    chain_hash: *mut UInt256,
    key: *mut Vec<u8>,
    mainnet: bool) -> bool {
    match base58::from(string) {
        Ok(all_data) => match all_data.len() {
            82 => {
                let data = &all_data[..78];
                let check_data = &all_data[78..];
                let equal = hashes::sha256d::Hash::hash(data).into_inner().eq(check_data);
                if equal {
                    let xprv = if mainnet { bip32::XPRV_MAINNET } else { bip32::XPRV_TESTNET };
                    let xpub = if mainnet { bip32::XPUB_MAINNET } else { bip32::XPUB_TESTNET };
                    if data != xprv && data != xpub {
                        return false;
                    }
                    let offset = &mut 4;
                    *depth = data.read_with::<u8>(offset, byte::LE).unwrap();
                    *fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
                    *child = data.read_with::<u32>(offset, byte::LE).unwrap();
                    *chain_hash = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                    if data == xprv {
                        *offset += 1;
                    }
                    *key = data[*offset..data.len() - *offset].to_vec();
                }
                equal
            },
            _ => false
        }
        Err(_) => false
    }
}

pub fn serialize32(depth: u8, fingerprint: u32, child: u32, chain: UInt256, key: &[u8], mainnet: bool) -> String {
    // NSMutableData *d = [NSMutableData secureDataWithCapacity:14 + key.length + sizeof(chain)];
    let offset = &mut 0;
    let mut d: Vec<u8> = Vec::with_capacity(14 + key.len() + 32);
    if key.len() < 33 {
        d.write_with(offset, if mainnet {bip32::XPRV_MAINNET} else {bip32::XPRV_TESTNET}, Default::default()).unwrap(); // 4
    } else {
        d.write_with(offset, if mainnet {bip32::XPUB_MAINNET} else {bip32::XPUB_TESTNET}, Default::default()).unwrap(); // 4
    }
    d.write_with::<u8>(offset, depth, byte::LE).unwrap(); // 5
    d.write_with::<u32>(offset, fingerprint, byte::LE).unwrap(); // 9
    d.write_with::<u32>(offset, child, byte::LE).unwrap(); // 13
    d.write_with(offset, chain.as_bytes(), Default::default()).unwrap(); // 45
    if key.len() < 33 {
        d.write_with(offset, b"\0".as_slice(), Default::default()).unwrap(); // 46 (prv) / 45 (pub)
    }
    d.write_with(offset, key, Default::default()).unwrap(); // 78 (prv) / 78 (pub)
    encode_slice(&d)
}

/// helper function for serializing BIP32 master public/private keys to standard export format
pub unsafe fn deserialize256<'a>(
    string: &'a str,
    depth: *mut u8,
    fingerprint: *mut u32,
    hardened: *mut bool,
    child: *mut UInt256,
    chain_hash: *mut UInt256,
    key: *mut Vec<u8>,
    mainnet: bool) -> bool {
    match base58::from(string) {
        Ok(all_data) => match all_data.len() {
            111 => {
                let data = &all_data[..107];
                let check_data = &all_data[107..];
                if hashes::sha256d::Hash::hash(data).into_inner().eq(check_data) {
                    let s = if mainnet { dip14::DPMS_MAINNET } else { dip14::DPTS_TESTNET };
                    let p = if mainnet { dip14::DPMP_MAINNET } else { dip14::DPTP_TESTNET };

                    if data != s && data != p {
                        return false;
                    }
                    let offset = &mut 4;
                    *depth = data.read_with::<u8>(offset, byte::LE).unwrap();
                    *fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
                    *hardened = data.read_with::<u8>(offset, byte::LE).unwrap() != 0;
                    *child = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                    *chain_hash = data.read_with::<UInt256>(offset, byte::LE).unwrap();

                    if data == if mainnet { dip14::DPMS_MAINNET } else { bip32::XPRV_TESTNET } {
                        *offset += 1;
                    }
                    *key = data[*offset..data.len() - *offset].to_vec();
                    true
                } else {
                    false
                }
            },
            _ => false
        },
        _ => false
    }
}
pub fn serialize256(depth: u8, fingerprint: u32, hardened: bool, child: UInt256, chain: UInt256, key: &[u8], mainnet: bool) -> String {
    //NSMutableData *d = [NSMutableData secureDataWithCapacity:47 + key.length + sizeof(chain)];
    let offset = &mut 0;
    let mut d: Vec<u8> = Vec::with_capacity(47 + key.len() + 32);
    if key.len() < 33 {
        d.write_with(offset, if mainnet {dip14::DPMS_MAINNET} else {dip14::DPTS_TESTNET}, Default::default()).unwrap(); // 4
    } else {
        d.write_with(offset, if mainnet {dip14::DPMP_MAINNET} else {dip14::DPTP_TESTNET}, Default::default()).unwrap(); // 4
    }
    d.write_with::<u8>(offset, depth, byte::LE).unwrap(); // 5
    d.write_with::<u32>(offset, fingerprint, byte::LE).unwrap(); // 9
    d.write_with::<u8>(offset, u8::from(hardened), byte::LE).unwrap(); // 10
    d.write_with(offset, child.as_bytes(), Default::default()).unwrap(); // 42
    d.write_with(offset, chain.as_bytes(), Default::default()).unwrap(); // 74
    if key.len() < 33 {
        d.write_with(offset, b"\0".as_slice(), Default::default()).unwrap(); // 75 (prv) / 74 (pub)
    }
    d.write_with(offset, key, Default::default()).unwrap(); // 107 (prv) / 107 (pub)
    encode_slice(&d)
}
