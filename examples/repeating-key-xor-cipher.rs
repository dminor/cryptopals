use std::env;
use std::fs::File;
use std::io::{self, Read, Write};

use cryptopals::repeating_key_xor_cipher;

pub fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);

    match args.next() {
        Some(key) => match args.next() {
            Some(input) => {
                let mut file = File::open(&input)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                let ciphered = repeating_key_xor_cipher(&contents, &key);
                let mut stdout = io::stdout();
                stdout.write_all(&ciphered)?;
            }
            None => {
                println!("error: input path not specified");
            }
        },
        None => {
            println!("error: key not specified");
        }
    }
    Ok(())
}
