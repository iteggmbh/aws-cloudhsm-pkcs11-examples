/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <common.h>
#include <stdlib.h>
#include <string.h>

/**
 * Generate an DES key with a template suitable for encrypting data.
 * The key is a Session key, and will be deleted once the HSM Session is closed.
 * @param session Active PKCS#11 session
 * @param key Location where the key's handle will be written
 * @return CK_RV
 */
CK_RV generate_des_key(CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_MECHANISM mech;

    mech.mechanism = CKM_DES3_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &true_val,             sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,     &true_val,             sizeof(CK_BBOOL)},
            {CKA_DECRYPT,     &true_val,             sizeof(CK_BBOOL)},
    };

    return funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
}

CK_RV find_des_key(CK_SESSION_HANDLE session,
                   CK_BYTE_PTR object_id,
                   CK_ULONG object_id_length,
                   CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;

    printf("Searching Object ID: ");
    print_bytes_as_hex(object_id, object_id_length);

    CK_ATTRIBUTE attr[] = {
        {CKA_OBJECT_ID, object_id, object_id_length},
    };

    rv = funcs->C_FindObjectsInit(session, attr, 1);

    if (rv != CKR_OK) {
        fprintf(stderr, "Can't initialize search\n");
        return rv;
    }

    CK_ULONG found = 0;

    rv = funcs->C_FindObjects(session, key, 1, &found);

    if (rv != CKR_OK) {
        fprintf(stderr, "FindObjects failed\n");
        return rv;
    }

    rv = funcs->C_FindObjectsFinal(session);

    if (rv != CKR_OK) {
        fprintf(stderr, "Can't finalize search\n");
        return rv;
    }

    if (found == 1) {
        fprintf(stderr, "Object ID not found.\n");
        key = CK_INVALID_HANDLE;
        rv = CKR_OBJECT_HANDLE_INVALID;
    }

    return rv;
}

/**
 * Encrypt and decrypt a string using DES ECB.
 * @param session Active PKCS#11 session
 */
CK_RV des_ecb_sample(CK_SESSION_HANDLE session,
                     CK_BYTE_PTR plaintext,
                     CK_ULONG plaintext_length,
                     CK_BYTE_PTR object_id,
                     CK_ULONG object_id_length
                     ) {
    CK_RV rv;
    CK_BYTE_PTR decrypted_ciphertext = NULL;

    // Find or Generate a DES key.
    CK_OBJECT_HANDLE des_key;

    if (object_id && object_id_length) {
        rv =find_des_key(session,object_id,object_id_length,&des_key);
        if (CKR_OK != rv) {
            fprintf(stderr, "Search for DES key failed: %lu\n", rv);
            return rv;
        }
    }
    else {
        rv = generate_des_key(session, &des_key);
        if (CKR_OK != rv) {
            fprintf(stderr, "DES key generation failed: %lu\n", rv);
            return rv;
        }
    }

    CK_ULONG ciphertext_length = 0;

    printf("Plaintext: ");
    print_bytes_as_hex(plaintext, plaintext_length);
    printf("Plaintext length: %lu\n", plaintext_length);

    // Prepare the mechanism
    CK_MECHANISM mech = {CKM_DES3_ECB, NULL, 0};

    //**********************************************************************************************
    // Encrypt
    //**********************************************************************************************

    rv = funcs->C_EncryptInit(session, &mech, des_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Encryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory will be required to hold the ciphertext.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);
    if (CKR_OK != rv) {
        fprintf(stderr, "Encryption failed: %lu\n", rv);
        return rv;
    }

    // Allocate the required memory.
    CK_BYTE_PTR ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        fprintf(stderr, "Could not allocate memory for ciphertext\n");
        return rv;
    }
    memset(ciphertext, 0, ciphertext_length);

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext, &ciphertext_length);
    if (CKR_OK != rv) {
        fprintf(stderr, "Encryption failed: %lu\n", rv);
        goto done;
    }

    // Print just the ciphertext in hex format
    printf("Ciphertext: ");
    print_bytes_as_hex(ciphertext, ciphertext_length);
    printf("Ciphertext length: %lu\n", ciphertext_length);

    //**********************************************************************************************
    // Decrypt
    //**********************************************************************************************

    rv = funcs->C_DecryptInit(session, &mech, des_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Decryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory is required to hold the decrypted text.
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, NULL, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        fprintf(stderr, "Decryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate memory for the decrypted ciphertext.
    decrypted_ciphertext = malloc(decrypted_ciphertext_length + 1); //We want to null terminate the raw chars later
    if (NULL == decrypted_ciphertext) {
        rv = 1;
        fprintf(stderr, "Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, decrypted_ciphertext, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        fprintf(stderr, "Decryption failed: %lu\n", rv);
        goto done;
    }
    decrypted_ciphertext[decrypted_ciphertext_length] = 0; // Turn the chars into a C-String via null termination

    printf("Decrypted ciphertext: ");
    print_bytes_as_hex(decrypted_ciphertext, decrypted_ciphertext_length);
    printf("Decrypted ciphertext length: %lu\n", decrypted_ciphertext_length);

done:
    if (NULL != decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }

    if (NULL != ciphertext) {
        free(ciphertext);
    }
    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    int rc = EXIT_FAILURE;
    unsigned char *object_id = NULL;
    ssize_t object_id_len = 0;
    unsigned char *plaintext = NULL;
    ssize_t plaintext_len = 0;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return rc;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return rc;
    }
    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return rc;
    }

    if (argv[1] == NULL) {
        fprintf(stderr, "No plaintext HEX string given\n");
        goto error;
    }

    plaintext_len = hexstring_to_new_bytes(argv[1],&plaintext);

    if (plaintext_len < 0) {
        fprintf(stderr, "Invalid plaintext HEX string [%s] given\n",argv[1]);
        goto error;
    }

    if (argv[2] != NULL) {

         object_id_len = hexstring_to_new_bytes(argv[1],&object_id);

        if (plaintext_len < 0) {
            fprintf(stderr, "Invalid object_id HEX string [%s] given\n",argv[2]);
            goto error;
        }

        if (argv[3] != NULL) {
            fprintf(stderr, "Extra arguments after object_id given\n");
            goto error;
        }
    }

    printf("\nEncrypt/Decrypt with DES ECB\n");
    rv = des_ecb_sample(session,plaintext,plaintext_len,object_id,object_id_len);
    if (CKR_OK == rv) {
        rc = EXIT_SUCCESS;
    }
    else {
        fprintf(stderr, "Failed des_ecb sample with rv=%lu\n", rv);
    }

error:
    pkcs11_finalize_session(session);
    if (object_id) {
      free(object_id);
    }
    if (plaintext) {
      free(plaintext);
    }

    return rc;
}
