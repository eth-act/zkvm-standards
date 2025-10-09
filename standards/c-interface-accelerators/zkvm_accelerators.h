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
 * Return codes
 * ============================================================================ */

/**
 * Status codes returned by zkVM accelerator functions
 */
typedef enum {
    ZKVM_ERROR = -1,            /* Operation failed */
    ZKVM_SUCCESS = 0,           /* Operation completed successfully */
    ZKVM_VERIFY_FAILURE = 1     /* Verification/check failed */
} zkvm_status;

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Hash output sizes */
#define ZKVM_HASH_KECCAK256_LEN 32
#define ZKVM_HASH_SHA256_LEN 32
#define ZKVM_HASH_RIPEMD160_LEN 20

/* secp256k1 sizes */
#define ZKVM_SECP256K1_HASH_LEN 32
#define ZKVM_SECP256K1_SIG_LEN 64
#define ZKVM_SECP256K1_PUBKEY_LEN 64

/* secp256r1 (P-256) sizes */
#define ZKVM_SECP256R1_HASH_LEN 32
#define ZKVM_SECP256R1_SIG_LEN 64
#define ZKVM_SECP256R1_PUBKEY_LEN 64

/* BN254 curve sizes */
#define ZKVM_BN254_G1_POINT_LEN 64
#define ZKVM_BN254_G2_POINT_LEN 128
#define ZKVM_BN254_SCALAR_LEN 32

/* BLS12-381 curve sizes */
#define ZKVM_BLS12_381_G1_POINT_LEN 96
#define ZKVM_BLS12_381_G2_POINT_LEN 192
#define ZKVM_BLS12_381_SCALAR_LEN 32
#define ZKVM_BLS12_381_FP_LEN 48
#define ZKVM_BLS12_381_FP2_LEN 96

/* BLAKE2f sizes */
#define ZKVM_BLAKE2F_STATE_LEN 64
#define ZKVM_BLAKE2F_MSG_LEN 128
#define ZKVM_BLAKE2F_OFFSET_LEN 16

/* KZG point evaluation sizes */
#define ZKVM_KZG_COMMITMENT_LEN 48
#define ZKVM_KZG_PROOF_LEN 48
#define ZKVM_KZG_FIELD_ELEMENT_LEN 32

/* ============================================================================
 * Non-Precompile Functions
 * ============================================================================ */

/**
 * Compute Keccak-256 hash
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param[out] output Pointer to ZKVM_HASH_KECCAK256_LEN-byte output buffer
 */
void zkvm_keccak256(const uint8_t* data, const size_t len, uint8_t output[ZKVM_HASH_KECCAK256_LEN]);

/**
 * secp256k1 signature verification
 *
 * Verifies an ECDSA signature on the secp256k1 curve.
 *
 * @param msg ZKVM_SECP256K1_HASH_LEN-byte message hash
 * @param sig ZKVM_SECP256K1_SIG_LEN-byte signature (r || s)
 * @param pubkey ZKVM_SECP256K1_PUBKEY_LEN-byte uncompressed public key (x || y)
 * @return ZKVM_SUCCESS if signature is valid, ZKVM_VERIFY_FAILURE if invalid, ZKVM_ERROR on error
 */
zkvm_status zkvm_secp256k1_verify(const uint8_t msg[ZKVM_SECP256K1_HASH_LEN],
                                  const uint8_t sig[ZKVM_SECP256K1_SIG_LEN],
                                  const uint8_t pubkey[ZKVM_SECP256K1_PUBKEY_LEN]);

/* ============================================================================
 * Ethereum Precompiles
 *
 * Note: These methods may not have the same API as the EVM precompiles because
 * in most cases, we care about the raw underlying cryptographic primitive.
 * ============================================================================ */

/**
 * ECRECOVER - Recover public key from signature (Precompile 0x01)
 *
 * Implements ecrecover precompile for secp256k1 signature recovery.
 * Note: The function as defined on the Ethereum layer returns an address.
 * We return a public key and the user will need to call Keccak manually.
 *
 *
 * @param msg ZKVM_SECP256K1_HASH_LEN-byte message hash
 * @param sig ZKVM_SECP256K1_SIG_LEN-byte signature (r || s)
 * @param recid Recovery ID
 * @param[out] output Pointer to ZKVM_SECP256K1_PUBKEY_LEN-byte output buffer (public key)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_secp256k1_ecrecover(const uint8_t msg[ZKVM_SECP256K1_HASH_LEN],
                                     const uint8_t sig[ZKVM_SECP256K1_SIG_LEN],
                                     uint8_t recid,
                                     uint8_t output[ZKVM_SECP256K1_PUBKEY_LEN]);

/**
 * Compute SHA-256 hash (Precompile 0x02)
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param[out] output Pointer to ZKVM_HASH_SHA256_LEN-byte output buffer
 */
void zkvm_sha256(const uint8_t* data, const size_t len, uint8_t output[ZKVM_HASH_SHA256_LEN]);

/**
 * Compute RIPEMD-160 hash (Precompile 0x03)
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param[out] output Pointer to ZKVM_HASH_RIPEMD160_LEN-byte output buffer
 */
void zkvm_ripemd160(const uint8_t* data, const size_t len, uint8_t output[ZKVM_HASH_RIPEMD160_LEN]);

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
 * @param[out] output Pointer to output buffer (must be exactly mod_len bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_modexp(const uint8_t* base, const size_t base_len,
                        const uint8_t* exp, const size_t exp_len,
                        const uint8_t* modulus, const size_t mod_len,
                        uint8_t* output);

/**
 * BN254 G1 point addition (Precompile 0x06, EIP-196)
 *
 * @param p1 First point (ZKVM_BN254_G1_POINT_LEN bytes: x || y)
 * @param p2 Second point (ZKVM_BN254_G1_POINT_LEN bytes: x || y)
 * @param[out] result Output point (ZKVM_BN254_G1_POINT_LEN bytes: x || y)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bn254_g1_add(const uint8_t p1[ZKVM_BN254_G1_POINT_LEN],
                              const uint8_t p2[ZKVM_BN254_G1_POINT_LEN],
                              uint8_t result[ZKVM_BN254_G1_POINT_LEN]);

/**
 * BN254 G1 scalar multiplication (Precompile 0x07, EIP-196)
 *
 * @param point Input point (ZKVM_BN254_G1_POINT_LEN bytes: x || y)
 * @param scalar ZKVM_BN254_SCALAR_LEN-byte scalar
 * @param[out] result Output point (ZKVM_BN254_G1_POINT_LEN bytes: x || y)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bn254_g1_mul(const uint8_t point[ZKVM_BN254_G1_POINT_LEN],
                              const uint8_t scalar[ZKVM_BN254_SCALAR_LEN],
                              uint8_t result[ZKVM_BN254_G1_POINT_LEN]);

/**
 * BN254 pairing check (Precompile 0x08, EIP-197)
 *
 * Checks if the pairing equation holds for the given points.
 *
 * @param input Encoded input points (G1, G2 pairs: ZKVM_BN254_G1_POINT_LEN + ZKVM_BN254_G2_POINT_LEN bytes each)
 * @param input_len Length of input in bytes (must be multiple of ZKVM_BN254_G1_POINT_LEN + ZKVM_BN254_G2_POINT_LEN)
 * @return ZKVM_SUCCESS if pairing check passes, ZKVM_VERIFY_FAILURE if pairing check fails, ZKVM_ERROR on error
 */
zkvm_status zkvm_bn254_pairing(const uint8_t* input, const size_t input_len);

/**
 * BLAKE2f compression function (Precompile 0x09, EIP-152)
 *
 * Implements the BLAKE2 compression function F.
 *
 * @param rounds Number of rounds (uint32, big-endian)
 * @param h State vector (ZKVM_BLAKE2F_STATE_LEN bytes: 8 × uint64 little-endian)
 * @param m Message block (ZKVM_BLAKE2F_MSG_LEN bytes: 16 × uint64 little-endian)
 * @param t Offset counters (ZKVM_BLAKE2F_OFFSET_LEN bytes: 2 × uint64 little-endian)
 * @param f Final block indicator (1 byte: 0x00 or 0x01)
 * @param[out] output Output state vector (ZKVM_BLAKE2F_STATE_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 *
 * @remark The use of big-endian encoding for the rounds parameter matches the specification in EIP-152.
 */
zkvm_status zkvm_blake2f(const uint32_t rounds,
                         const uint8_t h[ZKVM_BLAKE2F_STATE_LEN],
                         const uint8_t m[ZKVM_BLAKE2F_MSG_LEN],
                         const uint8_t t[ZKVM_BLAKE2F_OFFSET_LEN],
                         const uint8_t f,
                         uint8_t output[ZKVM_BLAKE2F_STATE_LEN]);

/**
 * Point evaluation precompile (Precompile 0x0a, EIP-4844)
 *
 * Verifies a KZG proof for point evaluation.
 *
 * @param commitment ZKVM_KZG_COMMITMENT_LEN-byte KZG commitment
 * @param z ZKVM_KZG_FIELD_ELEMENT_LEN-byte evaluation point
 * @param y ZKVM_KZG_FIELD_ELEMENT_LEN-byte claimed evaluation
 * @param proof ZKVM_KZG_PROOF_LEN-byte KZG proof
 * @return ZKVM_SUCCESS if proof is valid, ZKVM_VERIFY_FAILURE if proof is invalid, ZKVM_ERROR on error
 */
zkvm_status zkvm_kzg_point_eval(const uint8_t commitment[ZKVM_KZG_COMMITMENT_LEN],
                                const uint8_t z[ZKVM_KZG_FIELD_ELEMENT_LEN],
                                const uint8_t y[ZKVM_KZG_FIELD_ELEMENT_LEN],
                                const uint8_t proof[ZKVM_KZG_PROOF_LEN]);

/**
 * BLS12-381 G1 point addition (Precompile 0x0b, EIP-2537)
 *
 * @param p1 First G1 point (ZKVM_BLS12_381_G1_POINT_LEN bytes: Fp x, Fp y)
 * @param p2 Second G1 point (ZKVM_BLS12_381_G1_POINT_LEN bytes: Fp x, Fp y)
 * @param[out] result Output G1 point (ZKVM_BLS12_381_G1_POINT_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_g1_add(const uint8_t p1[ZKVM_BLS12_381_G1_POINT_LEN],
                              const uint8_t p2[ZKVM_BLS12_381_G1_POINT_LEN],
                              uint8_t result[ZKVM_BLS12_381_G1_POINT_LEN]);

/**
 * BLS12-381 G1 multi-scalar multiplication (Precompile 0x0c, EIP-2537)
 *
 * @param pairs Interleaved points and scalars (ZKVM_BLS12_381_G1_POINT_LEN + ZKVM_BLS12_381_SCALAR_LEN bytes per pair)
 * @param num_pairs Number of point-scalar pairs
 * @param[out] result Output G1 point (ZKVM_BLS12_381_G1_POINT_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_g1_msm(const uint8_t* pairs, const size_t num_pairs,
                              uint8_t result[ZKVM_BLS12_381_G1_POINT_LEN]);

/**
 * BLS12-381 G2 point addition (Precompile 0x0d, EIP-2537)
 *
 * @param p1 First G2 point (ZKVM_BLS12_381_G2_POINT_LEN bytes: Fp2 x, Fp2 y)
 * @param p2 Second G2 point (ZKVM_BLS12_381_G2_POINT_LEN bytes: Fp2 x, Fp2 y)
 * @param[out] result Output G2 point (ZKVM_BLS12_381_G2_POINT_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_g2_add(const uint8_t p1[ZKVM_BLS12_381_G2_POINT_LEN],
                              const uint8_t p2[ZKVM_BLS12_381_G2_POINT_LEN],
                              uint8_t result[ZKVM_BLS12_381_G2_POINT_LEN]);

/**
 * BLS12-381 G2 multi-scalar multiplication (Precompile 0x0e, EIP-2537)
 *
 * @param pairs Interleaved points and scalars (ZKVM_BLS12_381_G2_POINT_LEN + ZKVM_BLS12_381_SCALAR_LEN bytes per pair)
 * @param num_pairs Number of point-scalar pairs
 * @param[out] result Output G2 point (ZKVM_BLS12_381_G2_POINT_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_g2_msm(const uint8_t* pairs, const size_t num_pairs,
                              uint8_t result[ZKVM_BLS12_381_G2_POINT_LEN]);

/**
 * BLS12-381 pairing check (Precompile 0x0f, EIP-2537)
 *
 * @param pairs G1 and G2 point pairs (ZKVM_BLS12_381_G1_POINT_LEN + ZKVM_BLS12_381_G2_POINT_LEN bytes per pair)
 * @param num_pairs Number of point pairs
 * @return ZKVM_SUCCESS if pairing check passes, ZKVM_VERIFY_FAILURE if pairing check fails, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_pairing(const uint8_t* pairs, const size_t num_pairs);

/**
 * BLS12-381 map Fp to G1 (Precompile 0x10, EIP-2537)
 *
 * @param field_element ZKVM_BLS12_381_FP_LEN-byte Fp element
 * @param[out] result Output G1 point (ZKVM_BLS12_381_G1_POINT_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_map_fp_to_g1(const uint8_t field_element[ZKVM_BLS12_381_FP_LEN],
                                    uint8_t result[ZKVM_BLS12_381_G1_POINT_LEN]);

/**
 * BLS12-381 map Fp2 to G2 (Precompile 0x11, EIP-2537)
 *
 * @param field_element ZKVM_BLS12_381_FP2_LEN-byte Fp2 element
 * @param[out] result Output G2 point (ZKVM_BLS12_381_G2_POINT_LEN bytes)
 * @return ZKVM_SUCCESS on success, ZKVM_ERROR on error
 */
zkvm_status zkvm_bls12_map_fp2_to_g2(const uint8_t field_element[ZKVM_BLS12_381_FP2_LEN],
                                     uint8_t result[ZKVM_BLS12_381_G2_POINT_LEN]);

/**
 * secp256r1 (P-256) signature verification (Precompile 0x100, EIP-7212)
 *
 * @param msg ZKVM_SECP256R1_HASH_LEN-byte message hash
 * @param sig ZKVM_SECP256R1_SIG_LEN-byte signature (r || s)
 * @param pubkey ZKVM_SECP256R1_PUBKEY_LEN-byte uncompressed public key (x || y)
 * @return ZKVM_SUCCESS if signature is valid, ZKVM_VERIFY_FAILURE if invalid, ZKVM_ERROR on error
 */
zkvm_status zkvm_secp256r1_verify(const uint8_t msg[ZKVM_SECP256R1_HASH_LEN],
                                  const uint8_t sig[ZKVM_SECP256R1_SIG_LEN],
                                  const uint8_t pubkey[ZKVM_SECP256R1_PUBKEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ZKVM_ACCELERATORS_H */
