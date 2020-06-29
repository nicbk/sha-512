// SHA-512 implemented pursuant to NIST FIPS 180-4
// which is available at https://doi.org/10.6028/NIST.FIPS.180-4

#[cfg(test)]
mod tests;

const SHA512_CONST: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub enum HashError {
    InputTooLarge
}

pub struct Sha512 {
    hash: [u64; 8]
}

impl Sha512 {
    pub fn new(inp: &[u8]) -> Result<Sha512, HashError> {
        Ok(Sha512 {
            hash: sha512(inp)?
        })
    }

    pub fn to_string(&self) -> String {
        let mut hash_str = String::new();

        for x in &self.hash {
            hash_str += &format!("{:016x}", x)[..];
        }

        hash_str
    }
}

fn sha512(inp: &[u8]) -> Result<[u64; 8], HashError> {
    //if inp.len() > 1 << 124 {
    //    return Err(HashError::InputTooLarge);
    //}

    let mut hash: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let blocks = pad_data(inp);

    for block in blocks.iter() {
        sha512_block(&mut hash, block);
    }

    Ok(hash)
}

fn pad_data(inp: &[u8]) -> Vec<[u64; 16]> {
    use std::cmp::max;

    let inp_len_bits = inp.len() * 8;
    let num_blocks = max(((inp_len_bits as f64 / 1024_f64).ceil()
                   + ((inp_len_bits % 1024) as f64 / 896_f64)) as usize, 1);

    let mut blocks = vec![[0_u64; 16]; num_blocks];

    let mut block_num = 0;
    let mut block_pos = 0;

    for (i, x) in inp.iter().enumerate() {
        block_num = (i as f64 / 128_f64) as usize;
        block_pos = ((i % 128) as f64 / 8_f64) as usize;

        blocks[block_num][block_pos] |= (*x as u64) << 56 - (i % 8 * 8);
    }

    let final_u64 = inp.len() % 8;

    if final_u64 == 0 && inp.len() != 0 {
        if block_pos == 15 {
            block_pos = 0;
            block_num += 1;
        } else {
            block_pos += 1;
        }
    }

    blocks[block_num][block_pos] |= 128_u64 << 56 - (final_u64 * 8);

    blocks[num_blocks - 1][15] = (inp.len() * 8) as u64;
    //blocks[num_blocks - 1][14] = (inp.len() >> 64) as u64; 

    blocks
}

fn sha512_block(hash: &mut [u64; 8], block: &[u64; 16]) {
    use std::num::Wrapping;

    let mut w = [0_u64; 80];

    let mut var = [0_u64; 8];
    
    for (i, x) in hash.iter().enumerate() {
        var[i] = *x;
    }

    for i in 0..80 {
        if i < 16 {
            w[i] = block[i];
        } else {
            w[i] = (Wrapping(little_sigma_one(w[i-2])) + Wrapping(w[i-7]) + Wrapping(little_sigma_zero(w[i-15])) + Wrapping(w[i-16])).0;
        }

        let t_one = Wrapping(var[7]) + Wrapping(big_sigma_one(var[4])) + Wrapping(ch(var[4], var[5], var[6])) + Wrapping(SHA512_CONST[i]) + Wrapping(w[i]);
        let t_two = Wrapping(big_sigma_zero(var[0])) + Wrapping(maj(var[0], var[1], var[2]));

        var[7] = var[6];
        var[6] = var[5];
        var[5] = var[4];
        var[4] = (Wrapping(var[3]) + t_one).0;
        var[3] = var[2];
        var[2] = var[1];
        var[1] = var[0];
        var[0] = (t_one + t_two).0;
    }

    for i in 0..8 {
        hash[i] = (Wrapping(hash[i]) + Wrapping(var[i])).0;
    }
}

//fn sha512_block(hash: &mut [u64; 8], block: &[u64; 16]) {

//}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma_zero(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn big_sigma_one(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn little_sigma_zero(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn little_sigma_one(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
