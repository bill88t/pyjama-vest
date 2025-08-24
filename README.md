# Polarized Jumping Vigenère Cipher (Pyjama Vest)

## Core Algorithm

The Pyjama Vest Cipher is a byte-oriented symmetric encryption algorithm based on the classic Vigenère cipher with extended features, stacked to nullify all side channel attacks:

1. **Key Jumping**: Periodically jumps through the key to create non-linear patterns, always frequently enough to prohibit patterns
2. **Polarity Switching**: Alternates between addition and subtraction operations after each jump, further prohibiting guessing
3. **Multiple Passes**: The algorithm processes the entire data 10 times to increase security, jump and polarity states preserved, to maximize apparent noise

## Reference Implementation Key Structure

- **Header byte**: Fixed value 0xFF (1 byte)
- **Size identifier**: Key length in bytes (2 bytes, max 65535)
- **Jump frequency**: Controls how often jumps occur (1 byte)
- **Jump length**: Controls jump distance (3 bytes)
- **Key block**: The actual key data (variable length)
- **Finalizer byte**: Fixed value 0x00 (1 byte)

## Encryption Process

For each pass (repeated N times, 10 seems sufficient, variables PRESERVED):
1. For each byte in the data:
   a. Apply the current key byte value to the data byte:
      - If polarity is FALSE: Add key byte to data byte (modulo 256)
      - If polarity is TRUE: Subtract key byte from data byte (modulo 256)
   b. Move to the next key byte position
   c. Decrement jump countdown
   d. If jump countdown reaches zero:
      - Toggle polarity
      - Jump forward in the key by the jump length
      - Reset jump countdown
   e. If key position exceeds key length, wrap around (modulo key length)


## Decryption Process

It's the encryption process, ran in reverse.
The encryption is fully reversible so long as all the variables are known.

## Jump Mechanism

- **Jump frequency**: More aggressive at smaller message lengths
- **Jump interval**: How many bytes to process before jumping
- **Jump length**: How many positions to skip in the key when jumping

The jump interval is calculated as:

```
jump_interval = max((jump_frequency / 255) * (data_length // 16), 2)
```

The jump length is calculated as:

```
jump_length = (stored_jump_length // key_length) + key_length
```

## Polarity

Polarity determines whether the key bytes are added to or subtracted from the data bytes:
- FALSE (initial state): Addition operation
- TRUE: Subtraction operation

Polarity toggles each time a jump occurs, creating alternating patterns of encryption operations.

## Security Considerations

- The jumping mechanism breaks the regularity of standard Vigenère ciphers
- Multiple passes make it a blob of noise to statistical analysis
- Designed for embedded systems with minimal computational requirements
- Assembly-friendly with adequate short-term security
