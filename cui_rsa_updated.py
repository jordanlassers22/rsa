import random
import math
import hashlib

def is_prime(n):
    '''
    Helper function to check if a number is prime. Returns Boolean.

    Parameters
    ----------
    n : Int
        Function will determine if number n is prime or not.

    Returns
    -------
    bool
    '''
    # Checks if number is = 1. 1 is not a prime number
    if n <= 1:
        return False
    
    # Check if the number is 2 or 3, which are prime
    if n == 2 or n == 3:
        return True
    
    # Eliminate numbers divisible by 2 or 3 which aren't prime
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    # Start checking for divisors from 5 upwards, checking only numbers of the form 6k ± 1
    i = 5
    while i * i <= n:  # Only check up to the square root of n
        # If n is divisible by i or (i + 2), it's not prime
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6  # Increment by 6, as primes above 3 are of the form 6k ± 1
    
    # If no divisors were found, the number is prime
    return True

# Generates a prime number within a given range
def generate_random_prime(min_value=1000000, max_value=10000000):
    '''
    Helper function that generates a random prime number between 2 values

    Parameters
    ----------
    min_value : TYPE, int
        DESCRIPTION. Minimum value of desired prime number. The default is 1000000.
    max_value : TYPE, int
        DESCRIPTION. Maxium value of desired prime number. The default is 10000000.

    Returns
    -------
    num : TYPE
        DESCRIPTION.

    '''
    while True:
        num = random.randint(min_value, max_value)
        if is_prime(num):
            return num

def generate_e(phi): #Public exponent, part of public key
    e = 65537 #This number usually works and saves time
    if math.gcd(phi, e) == 1:
        return e
    while True:
        e = random.randint(1, phi)
        if math.gcd(phi, e) == 1:
            return e
    
def calculate_d(e, phi): #Private exponent part of private key
    return pow(e, -1, phi)
    
def encrypt(data, e, n):
    '''
    Encrypt a message using RSA encryption.

    Parameters
    ----------
    data : bytes
        The plaintext message to be encrypted.
    e : int
        The public exponent.
    n : int
        The modulus for both encryption and decryption.

    Returns
    -------
    bytes
        A byte string representing the encrypted message.
    '''
    ciphertext = b""
    block_size = (n.bit_length() + 7) // 8  # Calculate block size in bytes based on modulus length

    for num_pt in data:  # single byte
        ciphertext += pow(num_pt, e, n).to_bytes(block_size, byteorder = "big")  # same as c = num_pt^e mod n

    return ciphertext

def decrypt(ciphertext, d, n):
    '''
    Decrypt an RSA-encrypted message.

    Parameters
    ----------
    data : list of int
        The encrypted message, represented as a list of integers.
    d : int
        The private exponent.
    n : int
        The modulus for both encryption and decryption.

    Returns
    -------
    bytes
        The decrypted plaintext message.
    '''
    plaintext = b""
    block_size = (n.bit_length() +7) // 8
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypt_block = int.from_bytes(block, byteorder = "big")
        plaintext += pow(decrypt_block, d, n).to_bytes(1, byteorder="big")
    return plaintext

def sign(data, d, n):
    '''
    Generate a digital signature for a message using RSA.
    
    Parameters
    ----------
    data : bytes
        The message to sign.
    d : int
        The private exponent.
    n : int
        The modulus for both encryption and decryption.
    
    Returns
    -------
    str
        The digital signature as a hexadecimal string.

    '''
    sha256 = hashlib.sha256()
    sha256.update(data)
    hashval = sha256.digest()
    
    block_size = (n.bit_length() + 7) // 8 #Shorthand to round up to nearest byte
    signature = b""
    for num_pt in hashval:
        num_ct = pow(num_pt, d, n)
        ct_byte = num_ct.to_bytes(block_size, byteorder='big')
        signature += ct_byte
    return(signature)
       
def verify(data, signature, e, n):
    '''
    Verify a digital signature for a message.

    Parameters
    ----------
    data : bytes
        The message whose signature is being verified.
    signature : str
        The digital signature as a hexadecimal string.
    e : int
        The public exponent.
    n : int
        The modulus for both encryption and decryption.

    Returns
    -------
    bool
        True if the signature is valid, False otherwise.
    '''
    # Recompute the hash of the data
    sha256 = hashlib.sha256()
    sha256.update(data)
    hashval = sha256.digest()
    
    # Determine block size based on n's bit length, consistent with `sign`
    block_size = (n.bit_length() + 7) // 8
    
    # Decrypt each block of the signature to get the original hash
    decrypted_hash = b""
    for i in range(0, len(signature), block_size):
        num_ct = int.from_bytes(signature[i:i + block_size], byteorder='big')
        num_pt = pow(num_ct, e, n)
        decrypted_hash += num_pt.to_bytes(1, byteorder='big')
    
    # Compare the original and decrypted hashes
    return decrypted_hash == hashval
    
 # Generate all prime numbers up to a given limit using the Sieve of Eratosthenes.
def sieve_of_eratosthenes(limit):
    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False
    for num in range(2, int(limit**0.5) + 1):
        if is_prime[num]:
            for multiple in range(num * num, limit + 1, num):
                is_prime[multiple] = False
    return [num for num, prime in enumerate(is_prime) if prime]

#Attempts to factorize `n` by testing divisibility with small primes.
def factorize_n(n):
    limit = int(n**0.5)  # Only need primes up to the square root of n
    primes = sieve_of_eratosthenes(limit)
    
    for p in primes:
        if n % p == 0:  # Check if p is a factor of n
            q = n // p
            if p * q == n:
                return p, q
    return None  # No factors found within the limit

def evaluate_security(n):
    '''
   Evaluate the security of `n` by attempting to factorize it into two primes.

   Parameters
   ----------
   n : int
       The modulus `n` to evaluate.

   Prints
   ------
   None
       Prints a message indicating whether factors of `n` were found.
   '''
    result = factorize_n(n)
    if result:
        p_found, q_found = result
        print(f"Factors of N found: p = {p_found}, q = {q_found}")
    else:
        print("No factors found within the limit; N is likely secure.")
    


if __name__ == "__main__":
    
    n = 308366503433
    e = 65537
    og_message = b'The Ravens are the best team in the NFL.'
    og_sig = b'4Gt\xeb\x1fG\x06\xaft\x9539\xa4\xb6d@eW;\xe19p\xc4u\xd6\x1b\x98h\xe7\xd6\x07\xeac1\x8e<\xb3\xad\x86\xe9/|t\xb1N\x16\x15E\xdcn%\xbf-K\x04"\x9eW\x0c\x9c2\xc8\xb3x\xe1<\xb3\xad\x86\xe9\x02\xcc/Zh \x81\x01cs6\xcck\x06\x95"\xe4\xcc\xe0m\x08\xe4^\xc7\x84\x18\x16\x03\xe6\x1eC\x11\x1b\xd0\xd6Dy\x97\x1a\xd1$\xa5\xd0z\x9d\rqS\xc0\x8e\rqS\xc0\x8e\x1d \x04D\x16!\xcaw\xe9\xc7:*\x82f\x90\x07+\x9a\xdbL>\xa1\xef\xba\xf2<\xd3\xa0\xf0\x12\x0c\xf2\xa0\x9f\xa3'
    evaluate_security(n) # Crack p and q from n. Gives us p = 521357, q = 591469
    p = 521357
    q = 591469
    phi = (p-1) * (q-1)
    d = calculate_d(e, phi)
    
    print("\n")
    print(f"Original message said: {og_message}")
    print(f"Original signature was: {og_sig}")
    
    is_og_verified = verify(og_message, og_sig, e, n)
    print(f"Signature matches original message: {is_og_verified}")
    print("\n")
    
    new_message = b"Everybody gets 100% on the midterm!"
    new_sig = sign(new_message, d, n)
    print(f"New message is: {new_message}")
    print(f"New signature is: {new_sig}")
    is_new_sig_verified = verify(new_message, new_sig, e, n)
    print(f"Signature matches original message: {is_new_sig_verified}")
    
    # p = generate_random_prime()
    # q = generate_random_prime()
    # phi = (p-1) * (q-1) #Used to calculate private exponent or d
    # n = p * q #Modulus for both public and private keys. Public knowledge
    # e = generate_e(phi) #Public knowledge
    # d = calculate_d(e,phi) #Private knowledge
    
    # print("\n")
    # print("Generated keys:")
    # print(f"Public key (n, e): ({n}, {e})")
    # print(f"Private key (n, d): ({n}, {d})")
    # print("\n")
    # message = b"Hello, world!"
    
    # print(f"Message is: {message}")
    # ciphertext = encrypt(message, e, n)
    # print(f"Ciphertext: {ciphertext}")
    # print("\n")
    
    # decrypted_message = decrypt(ciphertext, d, n)
    # print(f"Decrypted Message: {decrypted_message}")
    # print("\n")
    
    # signature = sign(message, d, n)
    # print(f"Signature: {signature}")
    # print("\n")
    
    # is_valid = verify(message, signature, e, n)
    # print(f"Signature valid: {is_valid}")
    
    # evaluate_security(n)
   

