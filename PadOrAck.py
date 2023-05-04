from typing import Callable
from random import getrandbits


def encrypt_message(
        padding_oracle: Callable[[bytearray], bool],
        message_bytes: bytes,
        block_size: int = 16,
        verbose: bool = True
) -> str:
    iv_bytes = bytes(getrandbits(8) for _ in range(block_size))

    # If it is `0` then we must add a padding block.
    if len(message_bytes) % block_size == 0:
        message_bytes += bytes([block_size for _ in range(0, block_size)])
    else:
        padding_size = block_size - (len(message_bytes) % block_size)
        message_bytes += bytes([padding_size for _ in range(0, padding_size)])

    message_chunks = [message_bytes[i:i + block_size] for i in reversed(range(0, len(message_bytes), block_size))]
    result_chunks = [iv_bytes]

    for current_index, current_message_chunk in enumerate(message_chunks):
        if verbose:
            print("Encrypting message block {0} - {1}".format(current_index, current_message_chunk))

        # We have to crack the "result_chunk" at the `current_index` as this will give us the intermediary values for
        # the block that comes after it. We then use those intermediary values to create the cipher chunk at the
        # current index (that will be the next message chunk's "IV")
        current_intermediate_values = crack_block(padding_oracle, result_chunks[current_index], verbose)
        current_encrypted_chunk = bytes(map(lambda x, y: x ^ y, current_intermediate_values, current_message_chunk))

        if verbose:
            print("  Encrypted block {0} Result: {1}".format(current_index, current_encrypted_chunk.hex()))

        result_chunks.append(current_encrypted_chunk)

    if verbose:
        print()

    result_hex = ''.join(map(lambda chunk: chunk.hex(), reversed(result_chunks)))

    if verbose:
        print("Encrypted message: {0}".format(result_hex))

    return result_hex


def decrypt_message(
        padding_oracle: Callable[[bytearray], bool],
        cipher_bytes: bytes,
        block_size: int = 16,
        verbose: bool = True
) -> str:
    cipher_chunks = [cipher_bytes[i:i + block_size] for i in range(0, len(cipher_bytes), block_size)]

    result_intermediary_values = []

    # We skip the IV. No point in cracking a block we can't actually decrypt (and don't need to decrypt)
    for current_index, current_chunk in enumerate(cipher_chunks[1:]):
        if verbose:
            print("Cracking Block {0} - {1}".format(current_index, current_chunk.hex()))

        cracked_intermediary_values = crack_block(padding_oracle, current_chunk, verbose)

        if verbose:
            print("  Block {0} Result: {1}".format(current_index, cracked_intermediary_values.hex()))

        result_intermediary_values.append(cracked_intermediary_values)

    if verbose:
        print()

    # NOTE: For this we're making the assumption that the IV is the
    #       first block. Really, AFAIK it is impossible to crack the
    #       first block if it isn't the IV (unless they use null IV)
    result_plain_text = ""
    result_intermediate_values_bytes = b''

    for i in range(0, len(result_intermediary_values)):
        xor_result = bytes(map(lambda x, y: x ^ y, result_intermediary_values[i], cipher_chunks[i]))
        result_plain_text += xor_result.decode()

    for intermediate_value in result_intermediary_values:
        result_intermediate_values_bytes += intermediate_value

    # I'm sorry for the `str[:-ord(str[-1:])]`. It is removing the padding in the most condensed way I could think of.
    return result_plain_text[:-ord(result_plain_text[-1:])]


def crack_block(
        padding_oracle: Callable[[bytearray], bool],
        block: bytes,
        verbose: bool
) -> bytearray:
    block_size = len(block)
    intermediary_values = bytearray([0 for _ in range(0, block_size)])

    for current_byte in reversed(range(0, block_size)):
        if verbose:
            print("    Cracking Byte {0}".format(current_byte))

        current_padding_value = block_size - current_byte

        attempt_crack_block = bytearray([i for i in intermediary_values])

        # We need to prep the `attempt_crack_block` to have the intermediary values capable of resulting in the current
        # padding value.
        for prep in range(current_byte + 1, block_size):
            attempt_crack_block[prep] = attempt_crack_block[prep] ^ current_padding_value

        for i in range(0, 256):
            attempt_crack_block[current_byte] = i
            test_cipher = attempt_crack_block + block

            if padding_oracle(test_cipher):
                # We have to store the result in our `intermediary_values`. This value is the `attempt_crack_block`
                # value at the current byte xored with the current padding.
                intermediary_values[current_byte] = attempt_crack_block[current_byte] ^ current_padding_value

                if verbose:
                    print("        Found: {0}".format(hex(intermediary_values[current_byte])))

                break

    return intermediary_values
