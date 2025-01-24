#!/usr/bin/python3

"""
    Polarized Jumping Vigenère Cipher
    The "Pyjama Vest" Cipher

    Author: Bill Sideris (bill88t@feline.gr)
    Designed with embedded systems in mind.
"""

from os import urandom


def generate_key(key_len: int) -> bytes:
    """
    Generates a trully random key, given length. The key receives it's header information, and randomized jump offsets.

    Key structure:
        Header byte: 1 byte, always 0xff
        Size identifier: 2 bytes, holds hex key_len, maximum key size 65535
        Jump frequency: 1 byte
        Jump length: 3 bytes
        Key block: Specified key_len
        Finalizer byte: 1 byte, always 0x00
    """
    if not isinstance(key_len, int):
        raise TypeError("key_len must be an interger")
    if key_len < 4:  # The cipher can't realistically work with less than 4
        raise ValueError("Key must be at least 4 bytes long")
    if key_len > 65535:  # static block sizes limit size
        raise ValueError("Key can be at most 65535 bytes")

    key = (
        b"\xff" + key_len.to_bytes(2, byteorder="big") + urandom(key_len + 4) + b"\x00"
    )
    return key


def decode_key(key: bytes) -> dict:
    """
    Decodes and validates a provided key.
    For more information, refer to `generate_key()`.
    """

    if not isinstance(key, bytes):
        raise TypeError("Key must be a bytes object.")

    if len(key) < 8:  # Minimum size for the structure
        raise ValueError("Key is too short to be valid.")

    if key[0] != 0xFF:
        raise ValueError("Invalid header byte. Expected 0xff.")
    if key[-1]:  # Not zero
        raise ValueError("Invalid finalizer byte. Expected 0x00.")

    # Extract size identifier and validate
    key_len = int.from_bytes(key[1:3], byteorder="big")
    if len(key) != 8 + key_len:
        raise ValueError(
            f"Key length mismatch. Expected {key_len + 8} bytes, got {len(key)} bytes."
        )

    # Parse remaining parts
    jump_frequency = key[3]
    jump_length = int.from_bytes(key[4:7], byteorder="big")
    key_block = key[7:-1]

    return {
        "length": key_len,
        "jump_frequency": jump_frequency,
        "jump_length": jump_length,
        "block": key_block,
    }


def load_keyfile(file_path: str) -> bytes:
    """
    Load a key from the storage and validate it.
    """
    try:
        with open(file_path, "rb") as f:
            key = f.read()
        decode_key(key)
        return key
    except FileNotFoundError:
        raise FileNotFoundError(f"Key file '{file_path}' not found.")
    except ValueError as e:
        raise ValueError(f"Invalid key: {e}")
    except Exception as e:
        raise OSError(f"An error occurred while loading the key: {e}")


def generate_keyfile(file_path: str, length: int = 4096) -> None:
    """
    Generate a key and store it into a file.
    """
    with open(file_path, "wb") as f:
        key = generate_key(length)
        f.write(key)


def convert_key(input_str: str) -> bytes:
    """
    Generates a valid key from a given input string.
    For more information, refer to `generate_key()`.

    Use the first few bytes to make jump parameters.
    """

    if not isinstance(input_str, str):
        raise TypeError("Input must be a string.")

    # Encode the string and determine its length
    key_block = input_str.encode("utf-8")
    key_len = len(key_block)

    if key_len < 4:
        raise ValueError("The key must be at least 4 characters.")
    if key_len > 65535:
        raise ValueError(
            "Key is too long. Maximum supported length is 65535 characters."
        )

    # Arbitrary values for jump frequency and jump length
    jump_frequency = key_block[0]  # Use first byte
    jump_length = key_block[1:4]  # Use 2nd to 4th byte

    # Construct the key
    key = (
        b"\xff"  # Header byte
        + key_len.to_bytes(2, byteorder="big")  # Size identifier
        + bytes([jump_frequency])  # Jump frequency
        + jump_length  # Jump length
        + key_block  # Key block (encoded string)
        + b"\x00"  # Finalizer byte
    )
    return key


def jump_interval(length: int, frequency: int) -> int:
    """
    Calculate how often we jump across the key.

    We use jump frequency as a percentage value of the message length, divided by 16.
    Result is 2 to length div 16.
    """
    return int(max((frequency / 255) * (length // 16), 2))


def encrypt(data, key: bytes) -> bytes:
    """
    Encrypt a bytearray using the given key.

    Accepts input of key, not password.
    """

    if isinstance(data, bytes):
        data = bytearray(data)
    elif isinstance(data, str):
        data = bytearray(data.encode("utf-8"))
    elif isinstance(data, bytearray):
        pass
    else:
        raise TypeError("Accepted input data can be bytes, bytearray or string")

    data_len = len(data)
    key = decode_key(key)  # Decode key info into memory
    jump_chars = jump_interval(
        data_len, key["jump_frequency"]
    )  # Every how many characters we jump
    jump_len = (key["jump_length"] // key["length"]) + key[
        "length"
    ]  # How long the jump will be

    till_next_jump = jump_chars
    current_key_value = 0
    polarity = False

    for _ in range(10):
        for i in range(data_len):
            kv = data[i]
            if polarity:
                kv -= key["block"][current_key_value]
                if kv < 0:
                    kv += 256
            else:
                kv += key["block"][current_key_value]
                if kv > 255:
                    kv -= 256
            data[i] = kv
            till_next_jump -= 1
            current_key_value += 1
            if not till_next_jump:
                polarity = not polarity
                current_key_value += jump_len
                till_next_jump = jump_chars
            if current_key_value >= key["length"]:
                current_key_value %= key["length"]
    return bytes(data)


def decrypt(data, key: bytes):
    """
    Decrypt ciphertext data block using the given key.
    """
    if isinstance(data, bytes):
        data = bytearray(data)
    elif isinstance(data, str):
        data = bytearray(data.encode("utf-8"))
    elif isinstance(data, bytearray):
        pass
    else:
        raise TypeError("Accepted input data can be bytes, bytearray or string")

    data_len = len(data)
    key = decode_key(key)  # Decode key info into memory
    jump_chars = jump_interval(
        data_len, key["jump_frequency"]
    )  # Every how many characters we jump
    jump_len = (key["jump_length"] // key["length"]) + key[
        "length"
    ]  # How long the jump will be

    till_next_jump = jump_chars
    current_key_value = 0
    polarity = False

    for _ in range(10):
        for i in range(data_len):
            kv = data[i]
            if not polarity:
                kv -= key["block"][current_key_value]
                if kv < 0:
                    kv += 256
            else:
                kv += key["block"][current_key_value]
                if kv > 255:
                    kv -= 256
            data[i] = kv
            till_next_jump -= 1
            current_key_value += 1
            if not till_next_jump:
                polarity = not polarity
                current_key_value += jump_len
                till_next_jump = jump_chars
            if current_key_value >= key["length"]:
                current_key_value %= key["length"]
    return bytes(data)


def encrypt_file(input_file: str, output_file: str, key: bytes) -> None:
    """
    Encrypts the contents of a file in 4KB chunks and writes encrypted chunks to the output file.
    Each encrypted chunk is separated by a newline in the output file.
    """
    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        seperator = None
        retry = True
        sep_size = 2
        while retry:
            good = True
            sep_size += 1
            seperator = urandom(sep_size)
            if b"\n" in seperator:
                continue
            while chunk := infile.read(1024):
                if seperator in chunk:
                    good = False
                    break
            if good:
                retry = False
        infile.seek(0)
        outfile.write(seperator + b"\n")
        while chunk := infile.read(1024):
            encrypted_chunk = encrypt(chunk, key)
            outfile.write(encrypted_chunk.replace(b"\n", seperator) + b"\n")


def decrypt_file(input_file: str, output_file: str, key: bytes) -> None:
    """
    Decrypts a file previously encrypted in chunks and writes decrypted chunks to the output file.
    Each line in the input file is treated as an individual encrypted chunk.
    """
    with open(input_file, "rb") as infile, open(output_file, "wb") as outfile:
        seperator = infile.readline()[:-1]
        for line in infile:
            decrypted_chunk = decrypt(line[:-1].replace(seperator, b"\n"), key)
            outfile.write(decrypted_chunk)
