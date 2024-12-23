/* tslint:disable */
/* eslint-disable */
/**
 * Parses a raw email string into a structured `ParsedEmail` object.
 *
 * This function utilizes the `ParsedEmail::new_from_raw_email` method to parse the email,
 * and then serializes the result for JavaScript interoperability.
 *
 * # Arguments
 *
 * * `raw_email` - A `String` representing the raw email to be parsed.
 *
 * # Returns
 *
 * A `Promise` that resolves with the serialized `ParsedEmail` or rejects with an error message.
 */
export function parseEmail(raw_email: string): Promise<Promise<any>>;
/**
 * Generates a new `AccountCode` using a secure random number generator.
 *
 * This function creates a new `AccountCode` and serializes it for JavaScript interoperability.
 *
 * # Returns
 *
 * A `Promise` that resolves with the serialized `AccountCode` or rejects with an error message.
 */
export function generateAccountCode(): Promise<Promise<any>>;
/**
 * Generates an `AccountSalt` using a padded email address and an account code.
 *
 * This function converts the email address to a padded format, parses the account code,
 * and generates an `AccountSalt`, which is then serialized for JavaScript interoperability.
 *
 * # Arguments
 *
 * * `email_addr` - A `String` representing the email address.
 * * `account_code` - A `String` representing the account code in hexadecimal format.
 *
 * # Returns
 *
 * A `Promise` that resolves with the serialized `AccountSalt` or rejects with an error message.
 */
export function generateAccountSalt(email_addr: string, account_code: string): Promise<Promise<any>>;
/**
 * Pads an email address to a fixed length format.
 *
 * This function converts the email address to a padded format and serializes it
 * for JavaScript interoperability.
 *
 * # Arguments
 *
 * * `email_addr` - A `String` representing the email address to be padded.
 *
 * # Returns
 *
 * A `Promise` that resolves with the serialized padded email address or rejects with an error message.
 */
export function padEmailAddr(email_addr: string): Promise<Promise<any>>;
export function generateCircuitInputsWithDecomposedRegexesAndExternalInputs(email_addr: string, decomposed_regexes: any, external_inputs: any, params: any): Promise<Promise<any>>;
/**
 * Pads data for SHA-256 and extends it to a specified maximum length.
 *
 * This function pads the input data according to SHA-256 specifications and extends
 * it to a given maximum length. It returns both the padded data and the original
 * message length.
 *
 * # Arguments
 *
 * * `data` - A `Uint8Array` containing the data to be padded.
 * * `max_sha_bytes` - The maximum length in bytes to which the data should be extended.
 *
 * # Returns
 *
 * A `Promise` that resolves with an object containing the padded data and message length,
 * or rejects with an error message.
 */
export function sha256Pad(data: any, max_sha_bytes: number): Promise<Promise<any>>;
/**
 * Computes the Poseidon hash of a public key.
 *
 * # Arguments
 *
 * * `public_key_n` - A `Uint8Array` containing the public key in little endian format.
 *
 * # Returns
 *
 * A `Promise` that resolves with the hexadecimal string representation of the hash,
 * or rejects with an error message.
 */
export function publicKeyHash(public_key_n: any): Promise<Promise<any>>;
/**
 * Generates the circuit inputs for email verification circuits using the given email data, account code, and optional parameters.
 *
 * # Arguments
 *
 * * `email` - A `String` representing the raw email data to be verified.
 * * `account_code` - A `String` representing the account code in hexadecimal format.
 * * `params` - An object representing the optional parameters for the circuit.
 *
 * # Returns
 *
 * A `Promise` that resolves with the serialized `CircuitInputs` or rejects with an error message.
 */
export function generateEmailCircuitInput(email: string, account_code: string, params: any): Promise<Promise<any>>;
/**
 * Extracts the randomness from a given signature in the same manner as circuits.
 *
 * # Arguments
 *
 * * `signature` - A `Uint8Array` containing the signature data.
 *
 * # Returns
 *
 * A `Promise` that resolves with the extracted randomness as a hexadecimal string, or rejects with an error message.
 */
export function extractRandFromSignature(signautre: Uint8Array): Promise<Promise<any>>;
/**
 * Commits an email address using a given signature as the randomness.
 *
 * # Arguments
 *
 * * `email_addr` - A `String` representing the email address to be committed.
 * * `signature` - A `Uint8Array` containing the signature data to be used as randomness.
 *
 * # Returns
 *
 * A `Promise` that resolves with the commitment as a hexadecimal string, or rejects with an error message.
 */
export function emailAddrCommitWithSignature(email_addr: string, signautre: Uint8Array): Promise<Promise<any>>;
/**
 * Converts a byte array to a list of field elements.
 *
 * # Arguments
 *
 * * `bytes` - A `Uint8Array` containing the byte array to convert.
 *
 * # Returns
 *
 * A `Promise` that resolves with a list of field elements as hexadecimal strings, or rejects with an error message.
 */
export function bytesToFields(bytes: any): Promise<Promise<any>>;
/**
 * Computes the nullifier for an email address using a given signature.
 *
 * # Arguments
 *
 * * `signature` - A `Uint8Array` containing the signature data to be used for the nullifier.
 *
 * # Returns
 *
 * A `Promise` that resolves with the email nullifier as a hexadecimal string, or rejects with an error message.
 */
export function emailNullifier(signautre: Uint8Array): Promise<Promise<any>>;
/**
 * Extracts the indices of the invitation code in the given input string.
 *
 * # Arguments
 *
 * * `inputStr` - A `String` representing the input string to extract the invitation code indices from.
 *
 * # Returns
 *
 * A `Promise` that resolves with an array of arrays containing the start and end indices of the invitation code substrings,
 */
export function extractInvitationCodeIdxes(inputStr: string): Array<any>;
/**
 * Extracts the indices of the invitation code with prefix in the given input string.
 *
 * # Arguments
 *
 * * `inputStr` - A `String` representing the input string to extract the invitation code indices from.
 *
 * # Returns
 *
 * A `Promise` that resolves with an array of arrays containing the start and end indices of the invitation code substrings,
 */
export function extractInvitationCodeWithPrefixIdxes(inputStr: string): Array<any>;
export function padString(str: string, paddedBytesSize: number): Array<any>;
export function extractSubstrIdxes(inputStr: string, regexConfig: any, reveal_private: boolean): Array<any>;
export function extractSubstr(inputStr: string, regexConfig: any, reveal_private: boolean): Array<any>;
export function extractEmailAddrIdxes(inputStr: string): Array<any>;
export function extractEmailDomainIdxes(inputStr: string): Array<any>;
export function extractFromAllIdxes(inputStr: string): Array<any>;
export function extractFromAddrIdxes(inputStr: string): Array<any>;
export function extractToAllIdxes(inputStr: string): Array<any>;
export function extractToAddrIdxes(inputStr: string): Array<any>;
export function extractSubjectAllIdxes(inputStr: string): Array<any>;
export function extractBodyHashIdxes(inputStr: string): Array<any>;
export function extractTimestampIdxes(inputStr: string): Array<any>;
export function extractMessageIdIdxes(inputStr: string): Array<any>;
/**
 * Initializes wasm module, call this once before using functions of the package.
 * @returns {Promise<void>}
 */
export async function init(): Promise<void>;
