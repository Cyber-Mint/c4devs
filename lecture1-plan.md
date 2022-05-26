# Lecture One - Plan

1. Draw out the Cryptography mind map on white board & discuss as we expand it.
2. Order as follows:

    * Concepts (Discuss) 6 min
    * Mathematics (Worked examples) 3 min

      - XOR Table (Draw)
      - Modulus Mathematics (example)
      - mention the others<br>

    * Random Numbers (Discuss & worked CLI examples) 5 min
    * Secrets, Keys & Tokens ( Discuss & show jwt.io) 5 min
      
        - key size
        - key spreading (KDFs)
      
    * Hash Functions (Discuss & worked CLI examples)

        - `md5sum` & `sha256sum`
        - `hmac` & `export HMAC_KEY=$(openssl rand -hex 20)`

    * Ciphers - Symmetric
      * Stream Cipher (Board)
      * Feistel Encryption (Board)
      * Modes of Operation (Board)
      * AES (openssl CLI Examples)

    * Ciphers -Asymmetric
      * Concepts (Key Pairs, RSA vs EC - Discussion)
        * RSA key pairs ( board discussion)
        * EC suite of algorithms (Keys, Curves & Parameters)
      * Generic Public Key Cryptography (Alice, Bob & Mary - Board love triangle)
      * small diversion: TLS
      * RSA (python examples)
      * EC (ECC, ECDHE, ECDSA intro with python & openssl)
      * GPG (PKI in everyday use)

