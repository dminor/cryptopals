use aes::block_cipher::generic_array::GenericArray;
use aes::block_cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::HashMap;

fn from_hexdigit(c: char) -> Result<u8, &'static str> {
    match c {
        '0' => Ok(0),
        '1' => Ok(1),
        '2' => Ok(2),
        '3' => Ok(3),
        '4' => Ok(4),
        '5' => Ok(5),
        '6' => Ok(6),
        '7' => Ok(7),
        '8' => Ok(8),
        '9' => Ok(9),
        'a' | 'A' => Ok(10),
        'b' | 'B' => Ok(11),
        'c' | 'C' => Ok(12),
        'd' | 'D' => Ok(13),
        'e' | 'E' => Ok(14),
        'f' | 'F' => Ok(15),
        _ => {
            return Err("invalid hexadecimal digit");
        }
    }
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, &str> {
    let mut result = Vec::new();
    if s.len() % 2 != 0 {
        return Err("length must be multiple of two");
    }
    let as_digits = s
        .chars()
        .map(from_hexdigit)
        .collect::<Result<Vec<u8>, &str>>()?;
    for i in 0..as_digits.len() / 2 {
        result.push(as_digits[i * 2] * 16 + as_digits[i * 2 + 1]);
    }
    Ok(result)
}

pub fn from_base64(s: &str) -> Result<Vec<u8>, &str> {
    let mut result = Vec::new();
    let as_digits = s
        .chars()
        .filter_map(|c| match c {
            'A'..='Z' => Some(Ok(c as u8 - 'A' as u8)),
            'a'..='z' => Some(Ok(26 + c as u8 - 'a' as u8)),
            '0'..='9' => Some(Ok(52 + c as u8 - '0' as u8)),
            '+' => Some(Ok(62)),
            '/' => Some(Ok(63)),
            '=' => None,
            '\n' => None,
            _ => Some(Err("invalid base64 digit")),
        })
        .collect::<Result<Vec<u8>, &str>>()?;

    for chunk in as_digits.chunks(4) {
        match chunk.len() {
            4 => {
                let combined = ((chunk[0] as u32) << 18)
                    + ((chunk[1] as u32) << 12)
                    + ((chunk[2] as u32) << 6)
                    + chunk[3] as u32;
                result.push((combined >> 16) as u8);
                result.push(((combined >> 8) & 255) as u8);
                result.push((combined & 255) as u8);
            }
            3 => {
                let combined = ((chunk[0] as u32) << 18)
                    + ((chunk[1] as u32) << 12)
                    + ((chunk[2] as u32) << 6);
                result.push((combined >> 16) as u8);
                result.push(((combined >> 8) & 255) as u8);
            }
            2 => {
                let combined = ((chunk[0] as u32) << 18) + ((chunk[1] as u32) << 12);
                result.push((combined >> 16) as u8);
            }
            _ => {
                return Err("base64 file truncated");
            }
        }
    }

    Ok(result)
}

pub fn to_hex(v: &Vec<u8>) -> String {
    v.iter().map(|x| format!("{:02x}", x)).collect::<String>()
}

pub fn hex_to_base64(s: &str) -> Result<String, &str> {
    let mut result = Vec::new();

    let bytes = s
        .chars()
        .map(from_hexdigit)
        .collect::<Result<Vec<u8>, &str>>()?;
    let to_base64 = |c| match c {
        v @ 0..=25 => 65 + v,
        v @ 26..=51 => 71 + v,
        v @ 52..=63 => v - 4,
        _ => unreachable!(),
    };

    for i in (0..bytes.len()).step_by(3) {
        let total: u32 =
            (bytes[i] as u32) * 16 * 16 + (bytes[i + 1] as u32) * 16 + (bytes[i + 2] as u32);
        result.push(to_base64(total / 64) as u8);
        result.push(to_base64(total % 64) as u8);
    }

    // Handle trailing byte
    if bytes.len() % 3 == 2 {
        let total: u32 = (bytes[bytes.len() - 1] as u32) * 16 + (bytes[bytes.len() - 2] as u32);
        result.push(to_base64(total / 64) as u8);
        result.push(to_base64(total % 64) as u8);
    }

    match String::from_utf8(result) {
        Ok(s) => Ok(s),
        _ => Err("failed to convert to utf8"),
    }
}

pub fn fixed_xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::new();
    if a.len() != b.len() {
        return Err("buffers must be equal length");
    }
    for zipped in a.iter().zip(b.iter()) {
        result.push(zipped.0 ^ zipped.1);
    }

    Ok(result)
}

fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::new();

    for chunk in a.chunks(b.len()) {
        result.append(&mut fixed_xor(chunk, &b[0..chunk.len()])?);
    }

    Ok(result)
}

pub fn decipher_single_byte_xor_cipher(ciphertext: &[u8]) -> (usize, Vec<u8>) {
    let mut expected = HashMap::new();
    expected.insert('e', 0.11162 * ciphertext.len() as f64);
    expected.insert('t', 0.09356 * ciphertext.len() as f64);
    expected.insert('a', 0.08497 * ciphertext.len() as f64);
    expected.insert('i', 0.07587 * ciphertext.len() as f64);
    expected.insert('o', 0.07546 * ciphertext.len() as f64);
    expected.insert('n', 0.07507 * ciphertext.len() as f64);
    expected.insert('s', 0.06327 * ciphertext.len() as f64);
    expected.insert('h', 0.06094 * ciphertext.len() as f64);
    expected.insert('r', 0.07587 * ciphertext.len() as f64);
    expected.insert('d', 0.04253 * ciphertext.len() as f64);
    expected.insert('l', 0.04025 * ciphertext.len() as f64);
    expected.insert('u', 0.02758 * ciphertext.len() as f64);
    expected.insert(' ', 0.20000 * ciphertext.len() as f64);

    let score = |deciphered: &str| {
        let mut counts = HashMap::new();
        for c in expected.keys() {
            counts.insert(*c, 0);
        }
        for c in deciphered.to_lowercase().chars() {
            if let Some(entry) = counts.get_mut(&c) {
                *entry = *entry + 1;
            }
        }
        let mut chi_squared = 0.;
        for c in expected.keys() {
            let x = *expected.get(c).unwrap_or(&0.);
            let y = (*counts.get(c).unwrap_or(&0)) as f64;
            chi_squared += ((x - y) * (x - y)) / x;
        }

        chi_squared as usize
    };

    let mut best_score = usize::max_value();
    let mut best_guess = Vec::new();
    for c in 0..=255u8 {
        let deciphered = xor(ciphertext, &[c]).unwrap();
        if let Ok(as_utf8) = std::str::from_utf8(&deciphered) {
            let current_score = score(&as_utf8);
            if current_score < best_score {
                best_score = current_score;
                best_guess = deciphered;
            }
        }
    }
    (best_score, best_guess)
}

pub fn repeating_key_xor_cipher(plaintext: &[u8], key: &str) -> Vec<u8> {
    xor(plaintext, key.as_bytes()).unwrap()
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .fold(0, |acc, (c, d)| acc + (c ^ d).count_ones())
}

pub fn guess_repeating_key_xor_keysize(ciphertext: &[u8], max: usize) -> Vec<(f64, usize)> {
    let mut keysizes: Vec<(f64, usize)> = (2..=max)
        .map(|keysize| {
            let distance =
                hamming_distance(&ciphertext[0..keysize], &ciphertext[keysize..2 * keysize])
                    + hamming_distance(
                        &ciphertext[keysize..2 * keysize],
                        &ciphertext[2 * keysize..3 * keysize],
                    )
                    + hamming_distance(
                        &ciphertext[2 * keysize..3 * keysize],
                        &ciphertext[3 * keysize..4 * keysize],
                    );
            (distance as f64 / (5.0 * keysize as f64), keysize)
        })
        .collect();
    keysizes.sort_by(|x, y| x.partial_cmp(y).unwrap_or(Ordering::Equal));
    keysizes
}

pub fn decipher_repeating_key_xor_cipher(ciphertext: &[u8], keysize: usize) -> Vec<u8> {
    let mut blocks: Vec<Vec<u8>> = vec![Vec::new(); keysize];
    for chunk in ciphertext.chunks(keysize) {
        for i in 0..chunk.len() {
            blocks[i].push(chunk[i]);
        }
    }

    let deciphered: Vec<Vec<u8>> = blocks
        .par_iter()
        .map(|block| decipher_single_byte_xor_cipher(&block).1)
        .collect();

    let mut iters: Vec<std::slice::Iter<u8>> = Vec::new();
    for i in 0..keysize {
        iters.push(deciphered[i].iter());
    }

    let mut i = 0;
    let mut result: Vec<u8> = Vec::new();
    loop {
        match iters[i].next() {
            Some(v) => {
                result.push(*v);
            }
            None => {
                break;
            }
        }
        i += 1;
        if i == keysize {
            i = 0;
        }
    }

    result
}

pub fn aes_ecb_decipher(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(&key);
    let cipher = Aes128::new(&key);

    let mut plaintext = Vec::new();
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(&chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend(block.as_slice());
    }

    plaintext
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn challenge1() {
        assert_eq!(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
            Ok("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_owned()));
    }

    #[test]
    fn challenge2() {
        assert_eq!(
            to_hex(
                &fixed_xor(
                    &from_hex("1c0111001f010100061a024b53535009181c").unwrap(),
                    &from_hex("686974207468652062756c6c277320657965").unwrap()
                )
                .unwrap()
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }

    #[test]
    fn challenge3() {
        assert_eq!(
            decipher_single_byte_xor_cipher(
                &from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                    .unwrap()
            )
            .1,
            "Cooking MC\'s like a pound of bacon".as_bytes()
        );
    }

    #[test]
    fn challenge4() {
        let filename = "data/4.txt";
        let mut file = File::open(filename).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let guess = contents
            .split("\n")
            .collect::<Vec<&str>>()
            .par_iter()
            .map(|line| decipher_single_byte_xor_cipher(&from_hex(line).unwrap()))
            .min_by_key(|guess| guess.0);
        assert_eq!(
            guess.unwrap().1,
            "Now that the party is jumping\n".as_bytes()
        );
    }

    #[test]
    fn challenge5() {
        assert_eq!(
            &to_hex(&repeating_key_xor_cipher(
                "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes(),
                "ICE"
            )),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn test_from_base64() {
        // from https://en.wikipedia.org/wiki/Base64
        assert_eq!(
            from_base64("YW55IGNhcm5hbCBwbGVhcw==").unwrap(),
            "any carnal pleas".as_bytes()
        );
        assert_eq!(
            from_base64("YW55IGNhcm5hbCBwbGVhc3U=").unwrap(),
            "any carnal pleasu".as_bytes()
        );
        assert_eq!(
            from_base64("YW55IGNhcm5hbCBwbGVhc3Vy").unwrap(),
            "any carnal pleasur".as_bytes()
        );
        assert_eq!(
            from_base64("TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=").unwrap(),
            "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.".as_bytes()
        );
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
            37
        );
    }

    #[test]
    fn challenge6() {
        let filename = "data/6.txt";
        let mut file = File::open(filename).unwrap();
        let mut ciphertext = String::new();
        file.read_to_string(&mut ciphertext).unwrap();
        let ciphertext = from_base64(&ciphertext).unwrap();

        assert_eq!(
            guess_repeating_key_xor_keysize(&ciphertext, 40)[0..3],
            [(1.2, 2), (1.6, 3), (1.6758620689655173, 29)]
        );

        assert!(
            String::from_utf8(decipher_repeating_key_xor_cipher(&ciphertext, 29))
                .unwrap()
                .starts_with("I\'m back and I\'m ringin\' the bell \n")
        );
    }

    #[test]
    fn challenge7() {
        let filename = "data/7.txt";
        let mut file = File::open(filename).unwrap();
        let mut ciphertext = String::new();
        file.read_to_string(&mut ciphertext).unwrap();
        let ciphertext = from_base64(&ciphertext).unwrap();

        let key = "YELLOW SUBMARINE";
        assert!(
            String::from_utf8(aes_ecb_decipher(key.as_bytes(), &ciphertext))
                .unwrap()
                .starts_with("I\'m back and I\'m ringin\' the bell \n")
        );
    }

    #[test]
    fn challenge8() {
        let filename = "data/8.txt";
        let mut file = File::open(filename).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let guess = contents
            .split("\n")
            .collect::<Vec<&str>>()
            .par_iter()
            .filter(|line| line.len() > 0)
            .map(|line| {
                let line = from_hex(line).unwrap();
                let mut chunks = HashMap::new();
                for chunk in line.chunks(16) {
                    chunks.insert(chunk, true);
                }
                (chunks.len(), line)
            })
            .min_by_key(|guess| guess.0);
        assert_eq!(guess.unwrap().0, 7);
    }
}
