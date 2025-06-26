from Crypto.Util.number import getPrime
import random
from Crypto.Hash import SHA256

def dlogProof(x, g, p):
    # Step 1: Compute y = g^x (mod p)
    y = pow(g, x, p)
    
    # Step 2: Choose a random value r
    r = random.randint(1, p-1)
    
    # Step 3: Compute c = H(g, y, r) ← Fiat-Shamir启发式
    t = pow(g, r, p) # t = g^r (mod p)
    hash_input = str(g) + str(y) + str(t)
    c = int(SHA256.new(hash_input.encode()).hexdigest(), 16) % (p-1)
    
    # Step 4: Compute z = r + cx (mod p-1) 
    z = (r + c*x) % (p-1)
    
    # Step 5: Return the y and the proof pf = (c, z)
    return y, (c, z)

def dlogProofVerify(y, g, p, pf):
    # Step 1: Unpack the proof
    c, z = pf
    
    # Step 2: Compute t = g^z / y^c  = g^r (mod p)
    y_c_inv = pow(pow(y, c, p), p-2, p)  # y^c的逆元
    t = (pow(g, z, p) * y_c_inv) % p
    
    # Step 3: Recompute challenge c' = H(g, y, t)
    hash_input = str(g) + str(y) + str(t)
    c_computed = int(SHA256.new(hash_input.encode()).hexdigest(), 16) % (p-1)
    
    # Step 4: Return True if c == c_computed, else False
    return c == c_computed