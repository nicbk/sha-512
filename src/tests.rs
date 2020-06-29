use crate::*;

fn compare_hash(inp: &[u8], target_hash: &str) {
    let hash = Sha512::new(inp);
    match hash {
        Err(err) => match err {
            HashError::InputTooLarge =>
                panic!("Input data greater than 2^128 bits long")
        }

        Ok(res) => assert_eq!(res.to_string(), target_hash)
    }
}

#[test]
fn hash_none() {
    compare_hash(b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

#[test]
fn hash_some() {
    compare_hash(b"Hello, world!", "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421");
}

#[test]
fn hash_file() {
    use std::fs::read;

    let file_bytes = read("make-4.2.1.tar.gz")
        .expect("Unable to open file");

    compare_hash(&file_bytes[..], "d5f6ce3ac7c9a55cf8c1c04afa7d967dd311c9bb3167275ebb2649cf144f3740cf08450dc010a6acdea1fd529fd528a50b3c3381f4c9a7e83ec59b761817a038");
}
