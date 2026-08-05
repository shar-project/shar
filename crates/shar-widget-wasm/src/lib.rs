//! Optional browser accelerator for bounded RSW sequential squaring.
//!
//! The ABI is intentionally tiny and does not issue, price, or verify work.
//! JavaScript remains responsible for signed-plan validation, checkpointing,
//! progress, cancellation, and the universal `BigInt` fallback.

use num_bigint::BigUint;
use std::{mem, slice};

const MAX_INTEGER_BYTES: usize = 512;
const MAX_CHUNK_ITERATIONS: u32 = 65_536;

fn square_chunk(modulus_bytes: &[u8], value_bytes: &[u8], iterations: u32) -> Result<Vec<u8>, i32> {
    if modulus_bytes.is_empty()
        || modulus_bytes.len() > MAX_INTEGER_BYTES
        || value_bytes.is_empty()
        || value_bytes.len() > modulus_bytes.len()
        || iterations > MAX_CHUNK_ITERATIONS
    {
        return Err(-1);
    }
    let modulus = BigUint::from_bytes_be(modulus_bytes);
    let mut value = BigUint::from_bytes_be(value_bytes);
    if modulus <= BigUint::from(1_u8) || value >= modulus {
        return Err(-2);
    }
    for _ in 0..iterations {
        value = (&value * &value) % &modulus;
    }
    let mut output = value.to_bytes_be();
    if output.is_empty() {
        output.push(0);
    }
    Ok(output)
}

/// Reserve raw linear memory for one input or output buffer.
#[unsafe(no_mangle)]
pub extern "C" fn shar_alloc(length: u32) -> u32 {
    let Ok(capacity) = usize::try_from(length) else {
        return 0;
    };
    if capacity == 0 || capacity > MAX_INTEGER_BYTES {
        return 0;
    }
    let mut buffer = Vec::<u8>::with_capacity(capacity);
    let Ok(pointer) = u32::try_from(buffer.as_mut_ptr() as usize) else {
        return 0;
    };
    mem::forget(buffer);
    pointer
}

/// Release a buffer returned by [`shar_alloc`].
///
/// # Safety
/// `pointer` and `capacity` must be an unchanged live allocation from
/// `shar_alloc`, and each allocation must be released exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shar_dealloc(pointer: u32, capacity: u32) {
    if pointer == 0 || capacity == 0 || capacity > MAX_INTEGER_BYTES as u32 {
        return;
    }
    // SAFETY: The caller contract requires an unchanged allocation returned by
    // `shar_alloc`; length zero avoids reading uninitialized bytes.
    unsafe {
        drop(Vec::from_raw_parts(
            pointer as usize as *mut u8,
            0,
            capacity as usize,
        ));
    }
}

/// Execute one bounded sequential-squaring chunk.
///
/// Returns the positive output length, or a stable negative error code.
///
/// # Safety
/// Every pointer/length pair must reference live linear memory for the full
/// call. The output buffer must be writable and may not overlap either input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shar_square_chunk(
    modulus_pointer: u32,
    modulus_length: u32,
    value_pointer: u32,
    value_length: u32,
    iterations: u32,
    output_pointer: u32,
    output_capacity: u32,
) -> i32 {
    if modulus_pointer == 0 || value_pointer == 0 || output_pointer == 0 {
        return -3;
    }
    let Ok(modulus_length) = usize::try_from(modulus_length) else {
        return -3;
    };
    let Ok(value_length) = usize::try_from(value_length) else {
        return -3;
    };
    let Ok(output_capacity) = usize::try_from(output_capacity) else {
        return -3;
    };
    if modulus_length == 0
        || modulus_length > MAX_INTEGER_BYTES
        || value_length == 0
        || value_length > modulus_length
        || output_capacity == 0
        || output_capacity > MAX_INTEGER_BYTES
    {
        return -3;
    }
    // SAFETY: The caller contract provides live readable input regions.
    let modulus =
        unsafe { slice::from_raw_parts(modulus_pointer as usize as *const u8, modulus_length) };
    // SAFETY: The caller contract provides live readable input regions.
    let value = unsafe { slice::from_raw_parts(value_pointer as usize as *const u8, value_length) };
    let result = match square_chunk(modulus, value, iterations) {
        Ok(result) => result,
        Err(code) => return code,
    };
    if result.len() > output_capacity {
        return -4;
    }
    // SAFETY: The caller contract provides a live non-overlapping writable
    // output region with at least `output_capacity` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            result.as_ptr(),
            output_pointer as usize as *mut u8,
            result.len(),
        );
    }
    result.len() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_matches_direct_repeated_squaring() {
        let modulus = 1_000_036_000_099_u64;
        let mut expected = 123_456_789_u128;
        for _ in 0..37 {
            expected = (expected * expected) % u128::from(modulus);
        }
        assert_eq!(
            BigUint::from_bytes_be(
                &square_chunk(&modulus.to_be_bytes(), &123_456_789_u64.to_be_bytes(), 37).unwrap()
            ),
            BigUint::from(expected)
        );
    }

    #[test]
    fn bounds_and_invalid_values_fail_closed() {
        assert_eq!(square_chunk(&[], &[1], 1), Err(-1));
        assert_eq!(square_chunk(&[1], &[0], 1), Err(-2));
        assert_eq!(square_chunk(&[17], &[17], 1), Err(-2));
        assert_eq!(square_chunk(&[17], &[2], MAX_CHUNK_ITERATIONS + 1), Err(-1));
        assert_eq!(square_chunk(&[17], &[2], 0).unwrap(), vec![2]);
    }

    #[test]
    fn abi_rejects_oversized_lengths_before_reading_memory() {
        // These deliberately invalid pointers must remain unread because the
        // public ABI validates every length first.
        assert_eq!(
            unsafe {
                shar_square_chunk(
                    1,
                    MAX_INTEGER_BYTES as u32 + 1,
                    1,
                    1,
                    1,
                    1,
                    MAX_INTEGER_BYTES as u32,
                )
            },
            -3,
        );
        assert_eq!(
            unsafe { shar_square_chunk(1, 1, 1, 2, 1, 1, MAX_INTEGER_BYTES as u32) },
            -3,
        );
    }
}
