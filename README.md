# RSA Encryption and Digital Signature Implementation

This project implements RSA encryption, decryption, digital signature generation, and verification using Python. It also includes functions to generate random prime numbers, evaluate security by attempting to factorize the modulus, and compute necessary cryptographic values.

## Features

- **RSA Key Generation**: Generate prime numbers and compute public/private keys.
- **Encryption & Decryption**: Encrypt and decrypt messages using RSA.
- **Digital Signatures**: Sign and verify messages.
- **Security Evaluation**: Assess the security of an RSA modulus by attempting to factorize it.

## Requirements

This script requires Python 3 and the following standard libraries:

- `random`
- `math`
- `hashlib`

## Usage

### Key Generation

The script can generate random prime numbers and compute the public/private keys.

```python
p = generate_random_prime()
q = generate_random_prime()
n = p * q
phi = (p - 1) * (q - 1)
e = generate_e(phi)
d = calculate_d(e, phi)
```

Encrypting a Message
```python
message = b"Hello, world!"
ciphertext = encrypt(message, e, n)
print(f"Ciphertext: {ciphertext}")
```
Decrypting a Message
```python
decrypted_message = decrypt(ciphertext, d, n)
print(f"Decrypted Message: {decrypted_message}")
```

Signing a Message
```python
signature = sign(message, d, n)
print(f"Signature: {signature}")
```
Verifying a Signature
```python
is_valid = verify(message, signature, e, n)
print(f"Signature valid: {is_valid}")
```
Evaluating RSA Security
```python
evaluate_security(n)
```
Example Execution
```python
if __name__ == "__main__":
    n = 308366503433
    e = 65537
    message = b'The Ravens are the best team in the NFL.'
    signature = b'4Gt... (truncated)'
    
    evaluate_security(n)  # Attempts to factorize n
    
    p, q = 521357, 591469
    phi = (p-1) * (q-1)
    d = calculate_d(e, phi)
    
    is_verified = verify(message, signature, e, n)
    print(f"Signature matches original message: {is_verified}")
```
Notes

This implementation assumes e=65537 for efficiency.

Prime numbers are generated within a specified range to ensure security.

The script includes a factorization attempt to evaluate the security of n.

License

This project is open-source under the MIT License.

Author

Developed by Jordan Lassers
