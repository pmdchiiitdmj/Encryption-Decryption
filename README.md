# Encryption-Decryption
**1. RSA   FUNCTIONS
2. AES FUNCTIONS
3. Sample Input Output**



# RSA

**KeyGenration_RSA()**

>  P and Q are parameters
>     N = p*q
>     phi(N) = (p-1)*(Q-1);
>     after we have to calculate e
>     e = But e Must be
>     An integer. 	Not be a factor of n.
>     1 < e < Φ(n) [Φ(n) is discussed below],
>     Our Public Key is made of n and e
>     Generating Private Key :
>     We need to calculate Φ(n) :
>     Such that Φ(n) = (P-1)(Q-1)
>     Now calculate Private Key, d :
>      d = (k*Φ(n) + 1) / e for some integer k
>      
**Encrpt()**
> Encrypted Data = M^e mod N

**Decrpt()**

> Decrypted Data = (Encrypted Data)^d mod N

**getCryptoHash()**

> To calculate cryptographic hashing value in Java,  **MessageDigest** 
> Class is used, under the package java.security.
> 
> MessageDigest Class provides following cryptographic hash function to
> find hash value of a text, they are:  
> 1. MD5  
> 2. SHA-1  
> 3. SHA-256
> 
> This Algorithms are initialize in static method called 
> **getInstance()**. After selecting the algorithm it calculate the  **digest**  value and return the results in byte array.

**RSA Digital Signature Scheme:** 
 In RSA, d is private; e and n are public.

> -   Alice creates her digital signature using S=MD^d mod n where MD is the MessageDigest
> -   Alice sends encrypted Message M and Signature S to Bob
> -   Bob computes MD1=S^e mod n 
> -   If MD1=MD then Bob accepts the data sent by Alice.




## AES

### Predefined Arrays/ Values

    //Straight S box
    Sbox[]={0x09,0x04,0x0a,0x0b,0x0d,0x01,0x08,0x05,0x06,0x02,0x00,0x03,0x0c,0x0e,0x0f,0x07};
     
    //Straight S- Inverse box
    SIbox[]={0x0a,0x05,0x09,0x0b,0x01,0x07,0x08,0x0f,0x06,0x00,0x02,0x03,0x0c,0x04,0x0d,0x0e};
    
    //values of Round Constant
    RoundConstant[]={0x80,0xdf,0x30};
    
    //Standard matrix for Mix column
    MixMat[2][2]={{1,4},{4,1}};
    
    //Standard matrix for Inverse Mix column
    InMixMat[2][2]={{9,2},{2,9}};



**Substitute Nibble**
> - Divide all 16bits into Nibble  & store in t1,t2,t3,t4 variable and using s - box or S-Inv-box  
> - Finally merge all the value of t1,t2,t3,t4 and return it.

**Shift Rows**

>  - Shifting the 2nd and 4th nibble into right and left respectively

**Key Genration**

>  - Using value of Round Constant  , Substitute Nibble , Shift Rows and formula
>  we can calculate all the subkeys

**Round Key**
> - Key0  = w0w1,  key1  = w2w3  ,  key2  = w4w5

**Add Round Key**

> Plaintext XOR Round Key


**gmul**

> used for polynomial multiplication

**Bitmul**

> bitwise polynomial modulo 19 multiplication

**Mix Column**

> for multiply the matrix with nibbles of cipher text
> mix columns [1,4 ; 4,1] 
> encoding Inv Mix columns [9,2;2,9]
> 


## **Sample Input**

 

    Server side
           p = 7901
           q = 7907
    Client Side
		   p = 6991
		   q = 6997
		   plain text = hello!
		   secret Key = 1010101000111100
		   hashing Algo = MD5

## **Sample Output**

   **Client side**
    
    Plain Text:                                 hello!
	Secrete Key:                                1010101000111100
	public and private key parameters P and Q:  6991 6997
	client pblic key(e,N):                      951281 48916027
	The EncryptedSecretKey is:                  39129371
	The CipherText is:                          344aabec4802
	messagedigest:                              32010945
	The ClientSignature is:                     21804294
**Server Side**

    public and private key parameters P and Q:  7901 7907
    server pblic key(e,N):                      1004279 62473207
    The Decrypted Secret key: is:               1010101000111100
    The Decoded cipher text:                    hello!
    messagedigest:                              32010945
    The Intermediate verification code:         32010945
                          Signature Verified  :)
