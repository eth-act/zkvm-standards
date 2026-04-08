/**
 * zkVM U256 Arithmetic Accelerators C Interface
 *
 * This header defines the standard C interface for guest programs to access
 * accelerated 256-bit unsigned integer arithmetic in zkVMs.
 *
 * Design Notes:
 * - All values are represented as 32-byte big-endian byte arrays, matching
 *   EVM word encoding. This avoids endianness conversions at the EVM boundary.
 * - The zkvm_u256 type reuses zkvm_bytes_32 from zkvm_accelerators.h for
 *   consistency with the existing type system.
 * - Functions that can overflow or underflow (add, sub, mul) produce a
 *   full-width result (wrapping mod 2^256), matching EVM semantics.
 * - Division by zero: zkvm_u256_div and zkvm_u256_mod return zero when the
 *   divisor is zero, matching EVM semantics (no error/panic).
 * - addmod/mulmod with zero modulus return zero, matching EVM semantics.
 * - Comparison functions return their boolean result as a zkvm_u256 (0 or 1)
 *   rather than bool*, matching EVM stack semantics where all values are
 *   256-bit words. This avoids a widening conversion in the caller's hot path.
 * - The result pointer MAY alias any input pointer; implementations MUST
 *   produce correct results when input and output pointers overlap.
 *
 * Usage Notes:
 * - Caller MUST ensure all pointers are valid. If a function is called
 *   with a NULL pointer, the function SHOULD panic.
 * - The caller SHOULD allocate and free the input and output memory.
 * - This header includes zkvm_accelerators.h automatically.
 */

#ifndef ZKVM_U256_H
#define ZKVM_U256_H

#include "zkvm_accelerators.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Type definitions
 * ============================================================================ */

/**
 * 256-bit unsigned integer, stored as 32 bytes big-endian.
 */
typedef zkvm_bytes_32 zkvm_u256;

/* ============================================================================
 * Arithmetic operations
 *
 * These mirror the EVM arithmetic opcodes on 256-bit words.
 * All values are big-endian encoded.
 * ============================================================================ */

/**
 * U256 addition (wrapping)
 *
 * Opcode: 0x01 (ADD)
 *
 * Computes result = (a + b) mod 2^256.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_add(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * U256 subtraction (wrapping)
 *
 * Opcode: 0x03 (SUB)
 *
 * Computes result = (a - b) mod 2^256.
 *
 * @param a Pointer to first operand (minuend)
 * @param b Pointer to second operand (subtrahend)
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_sub(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * U256 multiplication (wrapping)
 *
 * Opcode: 0x02 (MUL)
 *
 * Computes result = (a * b) mod 2^256 (low 256 bits of the product).
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_mul(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * U256 integer division
 *
 * Opcode: 0x04 (DIV)
 *
 * Computes quotient = a / b (integer division, rounds toward zero).
 * If b is zero, quotient is set to zero (EVM semantics).
 *
 * @param a Pointer to dividend
 * @param b Pointer to divisor
 * @param[out] quotient Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_div(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* quotient);

/**
 * U256 modular reduction
 *
 * Opcode: 0x06 (MOD)
 *
 * Computes remainder = a % b.
 * If b is zero, remainder is set to zero (EVM semantics).
 *
 * @param a Pointer to dividend
 * @param b Pointer to modulus
 * @param[out] remainder Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_mod(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* remainder);

/**
 * U256 combined division and modular reduction
 *
 * Computes both quotient = a / b and remainder = a % b in a single operation.
 * If b is zero, both outputs are set to zero (EVM semantics).
 *
 * This avoids performing the expensive division algorithm twice when both
 * quotient and remainder are needed.
 *
 * @param a Pointer to dividend
 * @param b Pointer to divisor
 * @param[out] quotient Pointer to quotient output
 * @param[out] remainder Pointer to remainder output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_divmod(const zkvm_u256* a,
                             const zkvm_u256* b,
                             zkvm_u256* quotient,
                             zkvm_u256* remainder);

/**
 * U256 addition modulo N
 *
 * Opcode: 0x08 (ADDMOD)
 *
 * Computes result = (a + b) % n.
 * If n is zero, result is set to zero (EVM semantics).
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param n Pointer to modulus
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_addmod(const zkvm_u256* a,
                             const zkvm_u256* b,
                             const zkvm_u256* n,
                             zkvm_u256* result);

/**
 * U256 multiplication modulo N
 *
 * Opcode: 0x09 (MULMOD)
 *
 * Computes result = (a * b) % n.
 * Implementations MUST compute the full 512-bit product a*b before reducing
 * modulo n; truncating to 256 bits before reduction produces incorrect results.
 * If n is zero, result is set to zero (EVM semantics).
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param n Pointer to modulus
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_mulmod(const zkvm_u256* a,
                             const zkvm_u256* b,
                             const zkvm_u256* n,
                             zkvm_u256* result);

/**
 * U256 exponentiation
 *
 * Opcode: 0x0a (EXP)
 *
 * Computes result = (base ^ exponent) mod 2^256.
 *
 * @param base Pointer to base
 * @param exponent Pointer to exponent
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_exp(const zkvm_u256* base,
                          const zkvm_u256* exponent,
                          zkvm_u256* result);

/* ============================================================================
 * Signed arithmetic
 *
 * These handle two's complement signed interpretation of U256.
 * ============================================================================ */

/**
 * Signed U256 division (two's complement)
 *
 * Opcode: 0x05 (SDIV)
 *
 * Computes quotient = a / b where a and b are interpreted as signed
 * 256-bit two's complement integers. Rounds toward zero.
 * If b is zero, quotient is set to zero (EVM semantics).
 * The special case -2^255 / -1 = -2^255 (EVM semantics).
 *
 * @param a Pointer to dividend (signed, two's complement)
 * @param b Pointer to divisor (signed, two's complement)
 * @param[out] quotient Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_sdiv(const zkvm_u256* a,
                           const zkvm_u256* b,
                           zkvm_u256* quotient);

/**
 * Signed U256 modular reduction (two's complement)
 *
 * Opcode: 0x07 (SMOD)
 *
 * Computes remainder = a % b where a and b are interpreted as signed
 * 256-bit two's complement integers. The sign of the result matches
 * the sign of a (truncated division).
 * If b is zero, remainder is set to zero (EVM semantics).
 *
 * @param a Pointer to dividend (signed, two's complement)
 * @param b Pointer to modulus (signed, two's complement)
 * @param[out] remainder Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_smod(const zkvm_u256* a,
                           const zkvm_u256* b,
                           zkvm_u256* remainder);

/**
 * Signed U256 combined division and modular reduction
 *
 * Computes both quotient and remainder for signed division in a single
 * operation. Semantics match zkvm_u256_sdiv and zkvm_u256_smod respectively.
 * If b is zero, both outputs are set to zero (EVM semantics).
 *
 * @param a Pointer to dividend (signed, two's complement)
 * @param b Pointer to divisor (signed, two's complement)
 * @param[out] quotient Pointer to quotient output
 * @param[out] remainder Pointer to remainder output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_sdivmod(const zkvm_u256* a,
                              const zkvm_u256* b,
                              zkvm_u256* quotient,
                              zkvm_u256* remainder);

/* ============================================================================
 * Comparison operations
 *
 * Note: These return the result as a zkvm_u256 (0 or 1) rather than bool*,
 * matching EVM stack semantics where all values are 256-bit words.
 * ============================================================================ */

/**
 * U256 less-than comparison
 *
 * Opcode: 0x10 (LT)
 *
 * Computes result = (a < b) ? 1 : 0.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output (0 or 1)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_lt(const zkvm_u256* a,
                         const zkvm_u256* b,
                         zkvm_u256* result);

/**
 * U256 greater-than comparison
 *
 * Opcode: 0x11 (GT)
 *
 * Computes result = (a > b) ? 1 : 0.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output (0 or 1)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_gt(const zkvm_u256* a,
                         const zkvm_u256* b,
                         zkvm_u256* result);

/**
 * Signed U256 less-than comparison (two's complement)
 *
 * Opcode: 0x12 (SLT)
 *
 * Computes result = (a < b) ? 1 : 0, where a and b are signed.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output (0 or 1)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_slt(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * Signed U256 greater-than comparison (two's complement)
 *
 * Opcode: 0x13 (SGT)
 *
 * Computes result = (a > b) ? 1 : 0, where a and b are signed.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output (0 or 1)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_sgt(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * U256 equality check
 *
 * Opcode: 0x14 (EQ)
 *
 * Computes result = (a == b) ? 1 : 0.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output (0 or 1)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_eq(const zkvm_u256* a,
                         const zkvm_u256* b,
                         zkvm_u256* result);

/**
 * U256 is-zero check
 *
 * Opcode: 0x15 (ISZERO)
 *
 * Computes result = (a == 0) ? 1 : 0.
 *
 * @param a Pointer to operand
 * @param[out] result Pointer to output (0 or 1)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_iszero(const zkvm_u256* a,
                             zkvm_u256* result);

/* ============================================================================
 * Bitwise operations
 * ============================================================================ */

/**
 * U256 bitwise AND
 *
 * Opcode: 0x16 (AND)
 *
 * Computes result = a & b.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_and(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * U256 bitwise OR
 *
 * Opcode: 0x17 (OR)
 *
 * Computes result = a | b.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_or(const zkvm_u256* a,
                         const zkvm_u256* b,
                         zkvm_u256* result);

/**
 * U256 bitwise XOR
 *
 * Opcode: 0x18 (XOR)
 *
 * Computes result = a ^ b.
 *
 * @param a Pointer to first operand
 * @param b Pointer to second operand
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_xor(const zkvm_u256* a,
                          const zkvm_u256* b,
                          zkvm_u256* result);

/**
 * U256 bitwise NOT
 *
 * Opcode: 0x19 (NOT)
 *
 * Computes result = ~a.
 *
 * @param a Pointer to operand
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_not(const zkvm_u256* a,
                          zkvm_u256* result);

/**
 * U256 retrieve single byte
 *
 * Opcode: 0x1a (BYTE)
 *
 * Extracts the i-th byte from a (0 = most significant byte).
 * If i >= 32, result is set to zero (EVM semantics).
 * The extracted byte is placed in the least significant byte of result.
 *
 * @param i Byte offset from most significant byte (0-31)
 * @param a Pointer to value
 * @param[out] result Pointer to output (zero-extended byte)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_byte(const zkvm_u256* i,
                           const zkvm_u256* a,
                           zkvm_u256* result);

/**
 * U256 left shift
 *
 * Opcode: 0x1b (SHL)
 * EIP-145
 *
 * Computes result = value << shift. If shift >= 256, result is zero.
 * Note: parameter order matches EVM stack order (shift is popped first).
 *
 * @param shift Pointer to shift amount
 * @param value Pointer to value to shift
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_shl(const zkvm_u256* shift,
                          const zkvm_u256* value,
                          zkvm_u256* result);

/**
 * U256 logical right shift
 *
 * Opcode: 0x1c (SHR)
 * EIP-145
 *
 * Computes result = value >> shift (zero-fill). If shift >= 256, result is zero.
 * Note: parameter order matches EVM stack order (shift is popped first).
 *
 * @param shift Pointer to shift amount
 * @param value Pointer to value to shift
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_shr(const zkvm_u256* shift,
                          const zkvm_u256* value,
                          zkvm_u256* result);

/**
 * U256 arithmetic (signed) right shift
 *
 * Opcode: 0x1d (SAR)
 * EIP-145
 *
 * Computes result = value >> shift with sign extension. If shift >= 256,
 * result is 0 if value is positive, or all-ones if value is negative.
 * Note: parameter order matches EVM stack order (shift is popped first).
 *
 * @param shift Pointer to shift amount
 * @param value Pointer to value to shift (signed, two's complement)
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_sar(const zkvm_u256* shift,
                          const zkvm_u256* value,
                          zkvm_u256* result);

/* ============================================================================
 * Extended operations
 * ============================================================================ */

/**
 * U256 sign extension
 *
 * Opcode: 0x0b (SIGNEXTEND)
 *
 * Extends the sign bit at byte position b (0-indexed from least significant)
 * through the higher-order bytes. If b >= 31, value is returned unchanged.
 *
 * @param b Pointer to byte position (0 = extend from LSB, 30 = extend from byte 30)
 * @param value Pointer to value
 * @param[out] result Pointer to output
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_u256_signextend(const zkvm_u256* b,
                                 const zkvm_u256* value,
                                 zkvm_u256* result);

#ifdef __cplusplus
}
#endif

#endif /* ZKVM_U256_H */
