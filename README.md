# Cryptography 4 Developers

Presentation material for a rapid fire lecture on cryptography for developers.

![c4dev.png](out/cryptography/cryptography.png)

## Random Numbers

> **PRNG** (Pseudo Random Numbers)<br><br>
Linux offers the two files `/dev/random` & `/dev/urandom` for blocking & non-blocking random number generation.  Both rely on **CSPRNG** (cryptographically-secure pseudo-random number generator) in the Linux Kernel.<br><br>

```bash
dd if=/dev/urandom count=4 bs=1 of=rndint
od -An --format=dI rndint #display as a long integer
```
`openssl` includes a random function `rand` and allows for formatting in hex or base64, which may be utilised to generate random numbers for use as IV's, seeds etc, for example in CI pipelines or as required.

```bash
openssl rand -base64 10 | base64 --decode
openssl rand -hex 20 | xxd
openssl rand -hex 20 -out rndfile.hex
```

For interest you can quickly generate random words from a word dictionary in Linux as this example shows. This is useful for creating Plain Text files for testing encryption & decryption.

```bash
base64 /dev/urandom | head -c 1000 > random.txt
shuf -n 100 /usr/share/dict/words | fmt -w 72
```

Not to be out done, the BASH shell has `$RANDOM` env variable which uses `/dev/urandom` in the background.  Lets roll some dice!

```bash
$ cat dice.sh
#!/bin/bash

function roll_dice {
    min=1
    max=6
    number=$(expr $min + $RANDOM % $max)
    echo $number
}
```

## Encryption and Decryption


```bash
openssl enc -aes-256-cbc -pbkdf2 -in plain.txt -out encrypted.bin
openssl enc -d -aes-256-cbc -pbkdf2 -in encrypted.bin
```

```bash
echo "fox" | openssl enc -aes-256-cbc -a -pbkdf2 -md sha256 > encrypted.b64
cat encrypted.b64 | openssl enc -aes-256-cbc -a -md sha256 -pbkdf2 -d
```



## Useful Linux commands



**sha256sum**
> Generate and verify SHA256 hashes at the CLI

```
cat cryptography.puml | sha256sum > cryptography.sha256
cat cryptography.puml | sha256sum -c cryptography.sha256 
```




### RSA (Rivest,Shamir,Adleman) Encryption

References:
- https://thatsmaths.com/2016/08/11/a-toy-example-of-rsa-encryption/

---
Licensed under [Creative Commons Zero (CC)](./LICENSE)<br> 
Copyright &copy; 2022, Cyber-Mint (Pty) Ltd