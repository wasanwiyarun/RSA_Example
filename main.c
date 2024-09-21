#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

#include "rsa_key.h"

void handle_error()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void publicKey_encrypt_privateKey_decrypt_test()
{
    printf("**** publicKey_encrypt_privateKey_decrypt_test ****\r\n");

    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1. Load the public key from C array (DER format)
    const unsigned char *public_key_data = public_key_deviceA_der;
    EVP_PKEY *public_key = d2i_PUBKEY( NULL, &public_key_data, public_key_deviceA_der_len);
    if(NULL == public_key)
    {
        handle_error();
    }

    // 2. Message to be encrypted.
    const char *message = "Hello, RSA";
    unsigned char encrypted[256] = {0}; //Ensure the buffer is large enough for RSA size
    EVP_PKEY_CTX *encrypt_context = EVP_PKEY_CTX_new(public_key, NULL);
    if( NULL == encrypt_context)
    {
        handle_error();
    }

    if(EVP_PKEY_encrypt_init(encrypt_context) <= 0)
    {
        handle_error();
    }

    size_t encrypted_length = sizeof(encrypted);
    int encrypt_error_code = EVP_PKEY_encrypt(encrypt_context, encrypted, &encrypted_length, (unsigned char*) message, strlen(message));
    if(encrypt_error_code <= 0)
    {
        printf("encrypt_error_code:%d\r\n", encrypt_error_code);
        handle_error();
    }

    printf("Encrypted message (hex):\r\n");
    for(int i = 0; i< encrypted_length; i++)
    {
        if(i%16==0 && i!=0)
        {
            printf("\r\n");
        }
        printf("%02X", encrypted[i]);
    }

    printf("\r\n");

    // 3. Load the private key from C array
    const unsigned char *private_key_data = private_key_deviceA_der;
    EVP_PKEY *private_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &private_key_data, private_key_deviceA_der_len);
    if(NULL == private_key)
    {
        printf("private_key is NULL\r\n");
        handle_error();
    }

    // 4. Decrypt the message using the private key
    unsigned char decrypted[256] = {0};
    size_t decrypted_length = sizeof(decrypted);
    EVP_PKEY_CTX *decrypt_context = EVP_PKEY_CTX_new(private_key, NULL);

    if(NULL == decrypt_context)
    {
        handle_error();
    }

    if(EVP_PKEY_decrypt_init(decrypt_context) <=0 )
    {   
        handle_error();
    }

    int decrypt_error_code = 0;

    decrypt_error_code = EVP_PKEY_decrypt(decrypt_context, decrypted, &decrypted_length, encrypted, encrypted_length);

    if(decrypt_error_code <= 0)
    {
        handle_error();
    }

    printf("Decrypted message:%ld, %s\r\n", decrypted_length, decrypted);

    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(encrypt_context);
    EVP_PKEY_CTX_free(decrypt_context);
    EVP_cleanup();
    ERR_free_strings();    

}

void signature_test()
{

    printf("\r\n\r\n**** publicKey_encrypt_privateKey_decrypt_test ****\r\n");


    // Message to be signed
    const char *message = "This is the message to be singed.";

    // Step 1.  Hash the message
    unsigned char has[EVP_MAX_MD_SIZE] = {0};
    size_t hash_len = 0;

    // Step 2. Load the private key from C array (DER format)
    const unsigned char *private_key_data = private_key_deviceA_der;
    EVP_PKEY *private_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &private_key_data, private_key_deviceA_der_len);
    if(NULL == private_key)
    {
        printf("private_key is NULL\r\n");
        handle_error();
    }

    //Step 3: Create the context for signing
    EVP_MD_CTX *messageDigestSigningContext = EVP_MD_CTX_new();
    if(NULL == messageDigestSigningContext)
    {
        handle_error();
    }

    // Step 4. Initialize the context for signing with the private key and digest function (SHA-256)
    int errCode = EVP_DigestSignInit(messageDigestSigningContext, NULL, EVP_sha256(), NULL, private_key);
    if(errCode <= 0)
    {
        handle_error();
    }

    // Step 5: pass the message to be signed.
    errCode = EVP_DigestSignUpdate(messageDigestSigningContext, message, strlen(message));
    if(errCode <= 0 )
    {
        handle_error();
    }

    // Step 6: Determine the signature size
    size_t signed_length = 0;
    errCode = EVP_DigestSignFinal(messageDigestSigningContext, NULL, &signed_length);
    if(errCode <= 0)
    {
        handle_error();
    }

    // Step 7: Create a buffer for the signature
    unsigned char *signature = (unsigned char*) OPENSSL_malloc(signed_length);
    if(NULL == signature)
    {
        handle_error();
    }

    // Step 8: Generate the signature
    errCode = EVP_DigestSignFinal(messageDigestSigningContext, signature, &signed_length);
    if(errCode <= 0)
    {
        handle_error();
    }

     printf("Signature len:%ld, (hex):\r\n", signed_length);
    for(int i = 0; i< signed_length; i++)
    {
        if(i%16==0 && i!=0)
        {
            printf("\r\n");
        }
        printf("%02X", signature[i]);
    }

    printf("\r\n");

    // Step 9:  Load the public key from C array (DER format)
    const unsigned char *public_key_data = public_key_deviceA_der;
    EVP_PKEY *public_key = d2i_PUBKEY( NULL, &public_key_data, public_key_deviceA_der_len);
    if(NULL == public_key)
    {
        handle_error();
    }

    // Step 10: Create and initialize the verification context
    EVP_MD_CTX *messageDigestVerifyContext = EVP_MD_CTX_new();
    if(NULL == messageDigestVerifyContext)
    {
        handle_error();
    }

    // Step 11: Initialize verification context using the public key and SHA-256
    errCode = EVP_DigestVerifyInit(messageDigestVerifyContext, NULL, EVP_sha256(), NULL, public_key);
    if(errCode <= 0)
    {
        handle_error();
    }

    // Step 12: Provide the message to verify
    errCode = EVP_DigestVerifyUpdate(messageDigestVerifyContext, message, strlen(message));
    if(errCode <= 0)
    {
        handle_error();
    }

    errCode = EVP_DigestVerifyFinal(messageDigestVerifyContext, signature, signed_length);

    if(1 == errCode)
    {
        printf("Signature is valid ^_^\r\n");
    }
    else if(0 == errCode)
    {
        printf("Signature is invalid T_T\r\n");
    }
    else
    {
        handle_error();
    }
        

    EVP_MD_CTX_free(messageDigestSigningContext);
    EVP_MD_CTX_free(messageDigestVerifyContext);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    
    EVP_cleanup();
    ERR_free_strings();  

}

int main()
{
    printf("Program Start\r\n");

    publicKey_encrypt_privateKey_decrypt_test();
    signature_test();

    return 0;
}
