import random as rd
import math as m
from demo_euclid_extend import *

# check prime number
def is_prime(n):
    for i in range(2,int(n**0.5)+1):
        if n%i==0:
            return False
        
    return True

# generate random q and p are prime numbers, and n = p*q
def get_n():
    while(1):
        p = rd.randint(1,999)
        q = rd.randint(1,999)
        if is_prime(p) and is_prime(q):
            return p,q,p*q

# generate random public key e
def get_e(fi_n):
    while(1):
        e = rd.randint(1,fi_n)
        if m.gcd(e,fi_n)==1:
            return e

# generate private key d by euclid extend algorithm
def get_d(e,fi_n):
    while(1):
        d = modinv(e,fi_n)
        if (((e*d)%fi_n == 1) and (1< d <fi_n)):
            return d

# encode with c = x^e mod n
def RSA_encode(x,e,n):
    return (x**e) % n

# deocde with m = c^d mod n
def RSA_decode(en,d,n):
    return (en ** d) % n 

# gen_key function will return public key e,n and private key d
def gen_key():
    p,q,n = get_n()
    fi_n = (p-1)*(q-1)
    e = get_e(fi_n)
    d = get_d(e,fi_n)
    
    return e,d,n,fi_n,p,q

# Demo 1
# we will see full encode and decode process
# demo will print all needed number in generate key step: p,q,n,fi_n, public key e and private key d
# encoded after encode
# decoded after decode
def demo_1(m):
    p,q,n = get_n()
    fi_n = (p-1)*(q-1)
    e = get_e(fi_n)
    d = get_d(e,fi_n)
    
    print("m: ",m)
    print("p: ",p)
    print("q: ",q)
    print("n: ",n)
    print("fi_n",fi_n)
    print("e: ",e)
    print("d: ",d)
    encode = RSA_encode(m,e,n)
    print("encode: ",RSA_encode(m,e,n))
    print("decode: ",RSA_decode(encode,d,n))

# Demo 2
# we will apply RSA encoder to encode a string and decode it. 
def demo_2():
    # message
    str_in = "Hello World"
    print("Message: ",str_in)

    str_in = [char for char in str_in] # split string to character list
    x = [ord(char) for char in str_in] # parse char list to number list by ascii table
    
    print("char list: " ,str_in)
##    print(x)

    # generate public key, private key, n
    p_key,pr_key,n = gen_key()

    #use public key to encode number list
    encode = [RSA_encode(char,p_key,n) for char in x]

    # use private key to decode encoded list
    decode = [RSA_decode(char,pr_key,n) for char in encode]

    #record encoded string ( number list after encode, parse them to ascii and join them to string)   
    str_encode = " ".join(list(chr(el%256) for el in encode))

    #record decoded string ( number list after decode, parse them to ascii and join them to string)
    str_decode = "".join(list(chr(el) for el in decode))

##    print("encode",encode)
    print()
    print("encoded string: ",str_encode)
##    print("decode",decode)
    print("decoded string: ",str_decode)

##demo_1(5)
##print()
##demo_2()
