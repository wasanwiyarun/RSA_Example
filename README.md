
# RSA Encryption and Decryption with OpenSSL and C

This project demonstrates how to generate RSA keys using OpenSSL, convert them from PEM to DER format, and then use them in a C program for encryption and decryption.

## Prerequisites

To run this project, you'll need the following tools installed:

- OpenSSL
- GCC (or any C compiler)
- OpenSSL development libraries (for linking OpenSSL with C code)

## Steps to Generate and Convert RSA Keys

### Step 1: Generate RSA Private Key

Use the following command to generate a 2048-bit RSA private key:

```bash
$ mkdir rsa_key
$ cd ras_key
$ openssl genrsa -out private_key_deviceA.pem 2048
$ openssl genrsa -out private_key_deviceB.pem 2048
```

This will create a file named `private_key_deviceA.pem` containing the RSA private key.

### Step 2: Extract Public Key from Private Key

To extract the public key from the private key, use the following command:

```bash
$ openssl rsa -in private_key_deviceA.pem -pubout -out public_key_deviceA.pem
$ openssl rsa -in private_key_deviceB.pem -pubout -out public_key_deviceB.pem
```

This will generate a file named `public_key.pem` that contains the public key.

### Step 3: Convert PEM Files to DER Format

PEM is a base64-encoded format, while DER is a binary format, which is often more suitable for embedding in C programs.

#### Convert the Private Key to DER Format:

```bash
$ openssl rsa -in private_key_deviceA.pem -outform DER -out private_key_deviceA.der
$ openssl rsa -in private_key_deviceB.pem -outform DER -out private_key_deviceB.der

```

#### Convert the Public Key to DER Format:

```bash
$ openssl rsa -pubin -in public_key_deviceA.pem -outform DER -out public_key_deviceA.der
$ openssl rsa -pubin -in public_key_deviceB.pem -outform DER -out public_key_deviceB.der
```

Now you have the `private_key_deviceA.der` and `public_key.der` files, which you can use in your C program.




### Step 4: Convert DER Keys to const uint8_t * in C
#### Convert the Private Key DER Format to const uint8_t *:
Similarly, use xxd to convert the private key DER file to a C-compatible array:

```bash
$ xxd -i private_key_deviceA.der > private_key_deviceA.txt
$ xxd -i private_key_deviceB.der > private_key_deviceB.txt
```

This will generate a file private_key.h that contains the private key as a const uint8_t * array in C.

#### Convert the Public Key DER Format to const uint8_t *:
Use the xxd command to convert the public key DER file to a C-compatible array:

```bash
$ xxd -i public_key_deviceA.der > public_key_deviceA.txt
$ xxd -i public_key_deviceB.der > public_key_deviceB.txt
```

This will generate a file public_key.h that contains the public key as a const uint8_t * array in C.


## Steps to Compile the C Program

To compile the C program, you need to link it with the OpenSSL libraries. Use the following command to compile:

```bash
$ bash build.sh
```

This will generate an executable file named `rsa_example`.

## Running the Program

Make sure the `public_key.der` and `private_key_deviceA.der` files are in the same directory as the executable. You can run the program using the following command:

```bash
$ bash run.sh
```

The program will:
1. Load the RSA public key from `public_key.der` and encrypt a sample message.
2. Load the RSA private key from `private_key_deviceA.der` and decrypt the message.
3. Print the encrypted and decrypted message to the console.

## Notes

- The project uses RSA keys in DER format for encryption and decryption.
- OpenSSL's `RSA_public_encrypt` and `RSA_private_decrypt` functions are used for the encryption/decryption operations.
- This project uses `RSA_PKCS1_OAEP_PADDING` for padding, which enhances the security of RSA encryption.