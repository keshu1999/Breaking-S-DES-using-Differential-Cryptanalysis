## Breaking S-DES using Differential Cryptanalysis

The Simplified Data Encryption Standard (S-DES) is a reduced version of the Data Encryption Standard (DES) algorithm, designed to mimic the properties of DES while operating on smaller data units. Specifically, S-DES processes 8-bit message blocks using a 10-bit key, as opposed to the larger block and key sizes employed by DES. The algorithm consists of two rounds, during which the 10-bit key is used to generate two distinct 8-bit subkeys. Each subkey is applied during a specific iteration of the encryption process.


### Objective
* To perform differential cryptanalysis on the Simplified S-Box.
* To extract the main key, round 1 subkey, and round 2 subkey.


### Files
1. `Encrypt.py` : Encryption code
2. `Decrypt.py` : Decryption code
3. `Crack.py` : Differential cryptanalysis crack

### How to run
```
python Encrypt.py <plaintext file> <file to store ciphertext>
```