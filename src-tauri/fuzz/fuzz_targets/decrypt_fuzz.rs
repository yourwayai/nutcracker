#![no_main]

use libfuzzer_sys::fuzz_target;
use nutcracker::crypto::decrypt;

fuzz_target!(|data: &[u8]| {
    // Exercise decrypt() with arbitrary mutated byte streams and a fixed test key.
    // decrypt() must always return Ok(_) or Err(VaultError) without panicking.
    let fixed_key = [0x42u8; 32];
    let _ = decrypt(data, &fixed_key);

    // Also split the first 32 bytes as a fuzzed key when input is long enough.
    if data.len() > 32 {
        let (fuzzed_key_slice, blob) = data.split_at(32);
        let mut fuzzed_key = [0u8; 32];
        fuzzed_key.copy_from_slice(fuzzed_key_slice);
        let _ = decrypt(blob, &fuzzed_key);
    }
});
