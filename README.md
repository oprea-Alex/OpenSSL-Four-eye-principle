# OpenSSL-Four-eye-principle
C implementation of attacking a key blob based on a Four-eye principle. The main exploit is based on the public exponent's low value that doesn't exceeds the modulus.

Context:

Four-eye principle
To protect a secret code one uses a protection system that encrypts the code using the following four-eye-based protocol:

Random generate two initial secret keys k1 and k2, each of 56-bit length. 

From k1 and k2, generates a secret key k using the computation  k = SHA256 (k1  XOR  k2)

Encrypt the secret code with 256-bit variant of AES and using the secret key k. The ECB mode and PKCS7 padding scheme are used for AES. 

Encrypt each of the initial secret keys k1 and k2 using the RSA cryptosystem:
C1 = k1 ^ e1 mod n1, 
C2 = k2 ^ e2 mod n2, 

Where (e1, n1) and (e2, n2) are the RSA public keys of two key-officers, Alice and Bob.

Finally, all of these pieces are embedded in a single code-accessing blob using the next structure: 

|Len(C1)|           C1          |Len(C2)|           C2          |AESk(code)|
|2 bytes|       Len(C1) bytes   |2 bytes|       Len(C2) bytes   | 16 bytes |

Whenever the secret code has to be accessed, the 4-eye principle has to be applied meaning that both Alice and Bob use their RSA keys to get the secret needed to decrypt the code.

You have the mission to demonstrate this protection system is breakable and one could access the secret code with no requirement from the two key officers. 
You can find bellow the code-accessing blob and the RSA public keys of the two key-officers. 

Your flag is the secret code.

The code-accessing blob (hex encoding):

001893834DF42280C7A3D695ED87D986A2DD87E5BF43C4B5DEA50018172FFF3690221206BE2780BD99DC5A3C3A632D637595721D8E468C11326435BDA16CD0E7FDE4CC23

Alice’s public key:

-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAzjQuC7VtSzbFjU4FbEYx
MTWBQJTFh8zkXdiYhdDv/iH2k5XeZtm+6Zozz4MOrNRlyhcuqBjHyGmLp/DXz6VN
bHXQOSSFpnPXOM+W96xGFp/EJ4qhxLagcY7uFMfXS/tHIfKq1yxBPnmHnrDNGve2
taGhQaAyeXKkIn2X665aZgwzgVDiVjviBQFPqVT6U5HROOf6YzLhhPtCYaoiYLs/
gCLhJJfGu9POJuRVVPElEA0eQW7bxmXPSXQRRFbq4NIoFoYOV6YS+qzv1sbTn2Zh
I+pvT2HpdEvwx2S9L/j0PLdhCBQ7xUPX2Bg//d87JDYT1hOJImptwSVo0ZDaafvZ
7QIBAw==
-----END PUBLIC KEY-----

Bob’s public key:

-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAxXpbMNT1pMZaV/VwIDaO
sWW7XKY7bksSPpJ0NpleJl9wBmXEVh1HnWYFd9fdBtlsQXsVxqxUNBYS6FdsHzgp
G7Y0N7UZ4ISf3FKp12HmKxakfNM6Bj2rIYRPyFlCMZAvgmmKLNKgu8cm8cgKbSMe
msgdOoO46Ft11Ywa801sVCCEpXJFT7PVNepTYMhQ+vU8Mr8r/YPxwrKLxdoXh8XJ
tj7FrmylHCWYvA91QIQpe4h4i1XdlBcDg01rnNplJVJoDOI7agXCT9XsA8zNGJ++
iwoMT7Q+9xLOYVWw/rPjSBacpqH75DATpz7tMWw1bxPnXT1ShLTNnk41uB2qMZFf
ZQIBAw==
-----END PUBLIC KEY-----

========================================================================================================================================

 Write Up(RO):
 
  In rezolvarea temei am avut in vedere, in primul rand, faptul ca
dupa generarea celor 2 k1, k2 se face SHA256 pe XOR-ul lor, ceea ce
inseamna ca acesta ar trebui sa fie un end-point in rezolvarea
problemei, SHA-ul fiind, teoretic, ireversibil. Acest lucru m-a condus la
concluzia ca vulnerabilitatea ar trebui sa vina de la k1 si k2.

  Daca ne uitam la k1 si k2, vedem ca ele sunt pe (am descoperit
ulterior) 64 biti(8 bytes). Extragand din cheile publice ale lui Alice si Bob
exponentul public si modulul cu:
openssl.exe rsa -pubin -in .\alice.pubkey -text si
openssl.exe rsa -pubin -in .\bob.pubkey -text
observam ca ambii expoenenti e1 = e2 = 3 si ca modulele(deci si
lungimile cheilor) sunt ambele pe 2048 biti (256 bytes), ceea ce a
condus la presupunerea ca exponentierea lui k1 si k2 la 3 va duce la o
valoarea mai mica decat modulul(cu alte cuvinte, ki ^ 3 nu va trece de
modul), ceea ce inseamna ca ar putea fi gasite cu un simplu √ de ordin 3(Ki).

  Presupunerea anterioara a fost confirmata dupa ce am observat ca Ki
sunt pe 8 bytes, ceea ce ridicat la ei = 3 va duce la un rezultat fix pe 24
bytes(lungimea Ci-urilor din blob). Cu alte cuvinte, operatia de ridicare la
putere sigur nu poate depasi ca valoare modulul.

  Operatia de extragere a radacinilor cubice am realizat-o convertind
ciphertext-urile de 24 bytes din blob, C1 si C2, din Hexa in large integers
folosind un convertor online. Dupa, am extras radacina cubica din
fiecare Ci folosind: https://www.omnicalculator.com/math/cube-root .
Rezultatul calculului online l-am hardcodat in codul C in 2 unsigned long
long k1 si k2.

  Tot cea mai ramas de facut acum a fost calcularea
XOR-ului(rezultat scos in xor.out), deci obtinerea K-ului, conversia de la
ull la hex(cu ajutorul bn2bin() ) si de aplicat SHA256 pe K(rezultat scos
in md.out).

  In cele din urma, am aplicat decriptarea AES-256-ECB pe ultimii
16 octeti din blob(stocati in cipher.aes). Tinand cont de faptul ca am avut
un singur AES_BLOCK(deci 16 bytes), nu a fost nevoie de verificari
suplimentare pentru padding, acesta fiind de 2 octeti 0x02 0x02, pe care
insa nu i-am mai scris in fisierul decrypted.out.
Asadar, am obtinut un flag in ASCII, pe 14 bytes:
96381890757328.
















