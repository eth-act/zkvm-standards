/**
 * zkVM Cryptographic Accelerators C Interface
 *
 * This header defines the standard C interface for guest programs to access
 * accelerators in zkVMs.
 *
 * Note: Caller MUST ensure all pointers are valid. If a function is called
 *       with a NULL pointer, the function SHOULD panic.
 */

#ifndef ZKVM_ACCELERATORS_H
#define ZKVM_ACCELERATORS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Non-Precompile Functions
 * ============================================================================ */

/**
 * Compute Keccak-256 hash
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param output Pointer to 32-byte output buffer
 */
void zkvm_keccak256(const uint8_t* data, size_t len, uint8_t output[32]);

/* ============================================================================
 * Ethereum Precompiles
 * ============================================================================ */

/**
 * ECRECOVER - Recover public key from signature (Precompile 0x01)
 *
 * Implements Ethereum's ecrecover precompile for secp256k1 signature recovery.
 * Note: Returns 32-byte public key hash (last 20 bytes = address).
 *
 * @param msg 32-byte message hash
 * @param sig 64-byte signature (r || s)
 * @param recid Recovery ID
 * @param output Pointer to 32-byte output buffer (Keccak256 of pubkey)
 * @return 0 on success, -1 on error
 */
int zkvm_secp256k1_ecrecover(const uint8_t msg[32],
                             const uint8_t sig[64],
                             uint8_t recid,
                             uint8_t output[32]);

/**
 * Compute SHA-256 hash (Precompile 0x02)
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param output Pointer to 32-byte output buffer
 */
void zkvm_sha256(const uint8_t* data, size_t len, uint8_t output[32]);

/**
 * Compute RIPEMD-160 hash (Precompile 0x03)
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param output Pointer to 32-byte output buffer (20 bytes used, left-padded with zeros)
 TODO: Should we just return 20 bytes?
 */
void zkvm_ripemd160(const uint8_t* data, size_t len, uint8_t output[32]);

/**
 * The Identity/datacopy function (Precompile 0x04) is not provided as it
   can be implemented in the guest program efficiently.
 */

/**
 * Modular exponentiation (Precompile 0x05)
 *
 * Computes (base^exp) % modulus for arbitrary precision integers.
 *
 * @param base Pointer to base value bytes
 * @param base_len Length of base in bytes
 * @param exp Pointer to exponent bytes
 * @param exp_len Length of exponent in bytes
 * @param modulus Pointer to modulus bytes
 * @param mod_len Length of modulus in bytes
 * @param output Pointer to output buffer (must be exactly mod_len bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_modexp(const uint8_t* base, size_t base_len,
                const uint8_t* exp, size_t exp_len,
                const uint8_t* modulus, size_t mod_len,
                uint8_t* output);

/**
 * BN254 G1 point addition (Precompile 0x06, EIP-196)
 *
 * @param p1 First point (64 bytes: x || y)
 * @param p2 Second point (64 bytes: x || y)
 * @param result Output point (64 bytes: x || y)
 * @return 0 on success, -1 on error
 */
int zkvm_bn254_g1_add(const uint8_t p1[64], const uint8_t p2[64],
                      uint8_t result[64]);

/**
 * BN254 G1 scalar multiplication (Precompile 0x07, EIP-196)
 *
 * @param point Input point (64 bytes: x || y)
 * @param scalar 32-byte scalar
 * @param result Output point (64 bytes: x || y)
 * @return 0 on success, -1 on error
 */
int zkvm_bn254_g1_mul(const uint8_t point[64], const uint8_t scalar[32],
                      uint8_t result[64]);

/**
 * BN254 pairing check (Precompile 0x08, EIP-197)
 *
 * Checks if the pairing equation holds for the given points.
 *
 * @param input Encoded input points (G1, G2 pairs: 64 + 128 bytes each)
 * @param input_len Length of input in bytes (must be multiple of 192)
 * @return 1 if pairing check passes, 0 if pairing check fails, -1 on error
 */
int zkvm_bn254_pairing(const uint8_t* input, size_t input_len);

/**
 * BLAKE2f compression function (Precompile 0x09, EIP-152)
 *
 * Implements the BLAKE2 compression function F.
 *
 * @param rounds Number of rounds (uint32, big-endian)
 TODO: so this being in big endian was taken from the EIP. We don't need to match it but need to double check why
 * @param h State vector (64 bytes: 8 × uint64 little-endian)
 * @param m Message block (128 bytes: 16 × uint64 little-endian)
 * @param t Offset counters (16 bytes: 2 × uint64 little-endian)
 * @param f Final block indicator (1 byte: 0x00 or 0x01)
 * @param output Output state vector (64 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_blake2f(uint32_t rounds,
                 const uint8_t h[64],
                 const uint8_t m[128],
                 const uint8_t t[16],
                 uint8_t f,
                 uint8_t output[64]);

/**
 * Point evaluation precompile (Precompile 0x0a, EIP-4844)
 *
 * Verifies a KZG proof for point evaluation.
 *
 * @param commitment 48-byte KZG commitment
 * @param z 32-byte evaluation point
 * @param y 32-byte claimed evaluation
 * @param proof 48-byte KZG proof
 * @return 1 if proof is valid, 0 if proof is invalid, -1 on error
 */
int zkvm_kzg_point_eval(const uint8_t commitment[48],
                        const uint8_t z[32],
                        const uint8_t y[32],
                        const uint8_t proof[48]);

/**
 * BLS12-381 G1 point addition (Precompile 0x0b, EIP-2537)
 *
 * @param p1 First G1 point (128 bytes: Fp x, Fp y)
 * @param p2 Second G1 point (128 bytes: Fp x, Fp y)
 * @param result Output G1 point (128 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_bls12_g1_add(const uint8_t p1[128], const uint8_t p2[128],
                      uint8_t result[128]);

/**
 * BLS12-381 G1 multi-scalar multiplication (Precompile 0x0c, EIP-2537)
 *
 * @param pairs Interleaved points and scalars (128 + 32 bytes per pair)
 * @param num_pairs Number of point-scalar pairs
 * @param result Output G1 point (128 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_bls12_g1_msm(const uint8_t* pairs, const size_t num_pairs,
                      uint8_t result[128]);

/**
 * BLS12-381 G2 point addition (Precompile 0x0d, EIP-2537)
 *
 * @param p1 First G2 point (256 bytes: Fp2 x, Fp2 y)
 * @param p2 Second G2 point (256 bytes: Fp2 x, Fp2 y)
 * @param result Output G2 point (256 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_bls12_g2_add(const uint8_t p1[256], const uint8_t p2[256],
                      uint8_t result[256]);

/**
 * BLS12-381 G2 multi-scalar multiplication (Precompile 0x0e, EIP-2537)
 *
 * @param pairs Interleaved points and scalars (256 + 32 bytes per pair)
 * @param num_pairs Number of point-scalar pairs
 * @param result Output G2 point (256 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_bls12_g2_msm(const uint8_t* pairs, const size_t num_pairs,
                      uint8_t result[256]);

/**
 * BLS12-381 pairing check (Precompile 0x0f, EIP-2537)
 *
 * @param pairs G1 and G2 point pairs (128 + 256 bytes per pair)
 * @param num_pairs Number of point pairs
 * @return 1 if pairing check passes, 0 if pairing check fails, -1 on error
 */
int zkvm_bls12_pairing(const uint8_t* pairs, const size_t num_pairs);

/**
 * BLS12-381 map Fp to G1 (Precompile 0x10, EIP-2537)
 *
 * @param field_element 64-byte Fp element
 * @param result Output G1 point (128 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_bls12_map_fp_to_g1(const uint8_t field_element[64],
                            uint8_t result[128]);

/**
 * BLS12-381 map Fp2 to G2 (Precompile 0x11, EIP-2537)
 *
 * @param field_element 128-byte Fp2 element
 * @param result Output G2 point (256 bytes)
 * @return 0 on success, -1 on error
 */
int zkvm_bls12_map_fp2_to_g2(const uint8_t field_element[128],
                             uint8_t result[256]);

/**
 * secp256r1 (P-256) signature verification (Precompile 0x100, EIP-7212)
 *
 * @param msg 32-byte message hash
 * @param sig 64-byte signature (r || s)
 * @param pubkey 64-byte uncompressed public key (x || y)
 * @return 1 if signature is valid, 0 if invalid, -1 on error
 */
int zkvm_secp256r1_verify(const uint8_t msg[32],
                          const uint8_t sig[64],
                          const uint8_t pubkey[64]);

#ifdef __cplusplus
}
#endif

#endif /* ZKVM_ACCELERATORS_H */
