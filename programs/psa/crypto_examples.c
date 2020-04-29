#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT( predicate )                                                   \
    do                                                                        \
    {                                                                         \
        if( ! ( predicate ) )                                                 \
        {                                                                     \
            printf( "\tassertion failed at %s:%d - '%s'\r\n",         \
                    __FILE__, __LINE__, #predicate);                  \
            goto exit;                                                        \
        }                                                                     \
    } while ( 0 )

#define ASSERT_STATUS( actual, expected )                                     \
    do                                                                        \
    {                                                                         \
        if( ( actual ) != ( expected ) )                                      \
        {                                                                     \
            printf( "\tassertion failed at %s:%d - "                  \
                    "actual:%d expected:%d\r\n", __FILE__, __LINE__,  \
                            (psa_status_t) actual, (psa_status_t) expected ); \
            goto exit;                                                        \
        }                                                                     \
    } while ( 0 )

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_AES_C) || \
    !defined(MBEDTLS_CIPHER_MODE_CBC) || !defined(MBEDTLS_CIPHER_MODE_CTR) || \
    !defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and/or MBEDTLS_AES_C and/or "
            "MBEDTLS_CIPHER_MODE_CBC and/or MBEDTLS_CIPHER_MODE_CTR "
            "and/or MBEDTLS_CIPHER_MODE_WITH_PADDING "
            "not defined.\r\n" );
    return( 0 );
}
#else

static psa_status_t cipher_operation( psa_cipher_operation_t *operation,
                                      const uint8_t * input,
                                      size_t input_size,
                                      size_t part_size,
                                      uint8_t * output,
                                      size_t output_size,
                                      size_t *output_len )
{
    psa_status_t status;
    size_t bytes_to_write = 0, bytes_written = 0, len = 0;

    *output_len = 0;
    while( bytes_written != input_size )
    {
        bytes_to_write = ( input_size - bytes_written > part_size ?
                           part_size :
                           input_size - bytes_written );

        status = psa_cipher_update( operation, input + bytes_written,
                                    bytes_to_write, output + *output_len,
                                    output_size - *output_len, &len );
        ASSERT_STATUS( status, PSA_SUCCESS );

        bytes_written += bytes_to_write;
        *output_len += len;
    }

    status = psa_cipher_finish( operation, output + *output_len,
                                output_size - *output_len, &len );
    ASSERT_STATUS( status, PSA_SUCCESS );
    *output_len += len;

exit:
    return( status );
}

static psa_status_t cipher_encrypt( psa_key_handle_t key_handle,
                                    psa_algorithm_t alg,
                                    uint8_t * iv,
                                    size_t iv_size,
                                    const uint8_t * input,
                                    size_t input_size,
                                    size_t part_size,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t *output_len )
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    size_t iv_len = 0;

    memset( &operation, 0, sizeof( operation ) );
    status = psa_cipher_encrypt_setup( &operation, key_handle, alg );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = psa_cipher_generate_iv( &operation, iv, iv_size, &iv_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_operation( &operation, input, input_size, part_size,
                               output, output_size, output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

exit:
    psa_cipher_abort( &operation );
    return( status );
}

static psa_status_t cipher_decrypt( psa_key_handle_t key_handle,
                                    psa_algorithm_t alg,
                                    const uint8_t * iv,
                                    size_t iv_size,
                                    const uint8_t * input,
                                    size_t input_size,
                                    size_t part_size,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t *output_len )
{
    psa_status_t status;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    memset( &operation, 0, sizeof( operation ) );
    status = psa_cipher_decrypt_setup( &operation, key_handle, alg );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = psa_cipher_set_iv( &operation, iv, iv_size );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_operation( &operation, input, input_size, part_size,
                               output, output_size, output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

exit:
    psa_cipher_abort( &operation );
    return( status );
}

static psa_status_t
cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block( void )
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE( PSA_KEY_TYPE_AES ),
        key_bits = 256,
        part_size = block_size,
    };
    const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t key_handle = 0;
    size_t output_len = 0;
    uint8_t iv[block_size];
    uint8_t input[block_size];
    uint8_t encrypt[block_size];
    uint8_t decrypt[block_size];

    status = psa_generate_random( input, sizeof( input ) );
    ASSERT_STATUS( status, PSA_SUCCESS );

    psa_set_key_usage_flags( &attributes,
                             PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
    psa_set_key_algorithm( &attributes, alg );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_AES );
    psa_set_key_bits( &attributes, key_bits );

    status = psa_generate_key( &attributes, &key_handle );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_encrypt( key_handle, alg, iv, sizeof( iv ),
                             input, sizeof( input ), part_size,
                             encrypt, sizeof( encrypt ), &output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_decrypt( key_handle, alg, iv, sizeof( iv ),
                             encrypt, output_len, part_size,
                             decrypt, sizeof( decrypt ), &output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = memcmp( input, decrypt, sizeof( input ) );
    ASSERT_STATUS( status, PSA_SUCCESS );

exit:
    psa_destroy_key( key_handle );
    return( status );
}

static psa_status_t cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi( void )
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE( PSA_KEY_TYPE_AES ),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };

    const psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t key_handle = 0;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size],
            encrypt[input_size + block_size], decrypt[input_size + block_size];

    status = psa_generate_random( input, sizeof( input ) );
    ASSERT_STATUS( status, PSA_SUCCESS );

    psa_set_key_usage_flags( &attributes,
                             PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
    psa_set_key_algorithm( &attributes, alg );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_AES );
    psa_set_key_bits( &attributes, key_bits );

    status = psa_generate_key( &attributes, &key_handle );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_encrypt( key_handle, alg, iv, sizeof( iv ),
                             input, sizeof( input ), part_size,
                             encrypt, sizeof( encrypt ), &output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_decrypt( key_handle, alg, iv, sizeof( iv ),
                             encrypt, output_len, part_size,
                             decrypt, sizeof( decrypt ), &output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = memcmp( input, decrypt, sizeof( input ) );
    ASSERT_STATUS( status, PSA_SUCCESS );

exit:
    psa_destroy_key( key_handle );
    return( status );
}

static psa_status_t cipher_example_encrypt_decrypt_aes_ctr_multi( void )
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE( PSA_KEY_TYPE_AES ),
        key_bits = 256,
        input_size = 100,
        part_size = 10,
    };
    const psa_algorithm_t alg = PSA_ALG_CTR;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t key_handle = 0;
    size_t output_len = 0;
    uint8_t iv[block_size], input[input_size], encrypt[input_size],
            decrypt[input_size];

    status = psa_generate_random( input, sizeof( input ) );
    ASSERT_STATUS( status, PSA_SUCCESS );

    psa_set_key_usage_flags( &attributes,
                             PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
    psa_set_key_algorithm( &attributes, alg );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_AES );
    psa_set_key_bits( &attributes, key_bits );

    status = psa_generate_key( &attributes, &key_handle );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_encrypt( key_handle, alg, iv, sizeof( iv ),
                             input, sizeof( input ), part_size,
                             encrypt, sizeof( encrypt ), &output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = cipher_decrypt( key_handle, alg, iv, sizeof( iv ),
                             encrypt, output_len, part_size,
                             decrypt, sizeof( decrypt ), &output_len );
    ASSERT_STATUS( status, PSA_SUCCESS );

    status = memcmp( input, decrypt, sizeof( input ) );
    ASSERT_STATUS( status, PSA_SUCCESS );

exit:
    psa_destroy_key( key_handle );
    return( status );
}

static void cipher_examples( void )
{
    psa_status_t status;

    printf( "cipher encrypt/decrypt AES CBC no padding:\r\n" );
    status = cipher_example_encrypt_decrypt_aes_cbc_nopad_1_block( );
    if( status == PSA_SUCCESS )
        printf( "\tsuccess!\r\n" );

    printf( "cipher encrypt/decrypt AES CBC PKCS7 multipart:\r\n" );
    status = cipher_example_encrypt_decrypt_aes_cbc_pkcs7_multi( );
    if( status == PSA_SUCCESS )
        printf( "\tsuccess!\r\n" );

    printf( "cipher encrypt/decrypt AES CTR multipart:\r\n" );
    status = cipher_example_encrypt_decrypt_aes_ctr_multi( );
    if( status == PSA_SUCCESS )
        printf( "\tsuccess!\r\n" );
}

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    printf( "%s:%i: Input param failed - %s\n",
                    file, line, failure_condition );
    exit( EXIT_FAILURE );
}
#endif

void sign_a_message_using_ecdsa(const uint8_t *key, size_t key_len)
{
    enum { ECDSA_P256_KEY_SIZE_IN_BYTES = 32 };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t hash[32] = {0x50, 0xd8, 0x58, 0xe0, 0x98, 0x5e, 0xcc, 0x7f,
                        0x60, 0x41, 0x8a, 0xaf, 0x0c, 0xc5, 0xab, 0x58,
                        0x7f, 0x42, 0xc2, 0x57, 0x0a, 0x88, 0x40, 0x95,
                        0xa9, 0xe8, 0xcc, 0xac, 0xd0, 0xf6, 0x54, 0x5c};
    uint8_t signature[PSA_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_length;
    psa_key_handle_t handle;

    printf("Sign a message...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Set key attributes */
    psa_key_id_t key_id = 17;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT |
                                         PSA_KEY_USAGE_SIGN |
                                         PSA_KEY_USAGE_VERIFY);
    psa_set_key_algorithm(&attributes,
                          PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1));
    psa_set_key_bits(&attributes, ECDSA_P256_KEY_SIZE_IN_BYTES * 8);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attributes, key_id);

    /* XXX attestation checks this first */
    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1))) {
        printf("Not ECC key pair\n");
        return; // (PSA_ERROR_INVALID_ARGUMENT);
    }

    /* XXX Attestation also checks this */
    if (key_len != ECDSA_P256_KEY_SIZE_IN_BYTES) {
        printf("Bad key size\n");
        return; // PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Attestation attempts to open first */
    status = psa_open_key(key_id, &handle);
    if (status == PSA_SUCCESS) {
        /* The key already has been injected */
        goto export;
    }

    /* Import the key */
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import key\n");
        return;
    }

export:
    /* Export public key */
    {
    uint8_t *public_key_data[ECDSA_P256_KEY_SIZE_IN_BYTES];
    size_t public_key_data_size = sizeof(public_key_data);
    size_t public_key_data_length = 0;
    status = psa_export_public_key(handle,
                                   public_key_data,
                                   public_key_data_size,
                                   &public_key_data_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to export public key\n");
        return;
    }
    printf("\n\tpublic key length %u\n", public_key_data_length);
    }

    /* Sign message using the key */
    status = psa_sign_hash(handle, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
                           hash, sizeof(hash),
                           signature, sizeof(signature),
                           &signature_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to sign\n");
        return;
    }

    printf("Signed a message\n");

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static const uint8_t RSA_KEY[] =
{
    0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xaf,
    0x05, 0x7d, 0x39, 0x6e, 0xe8, 0x4f, 0xb7, 0x5f, 0xdb, 0xb5, 0xc2, 0xb1,
    0x3c, 0x7f, 0xe5, 0xa6, 0x54, 0xaa, 0x8a, 0xa2, 0x47, 0x0b, 0x54, 0x1e,
    0xe1, 0xfe, 0xb0, 0xb1, 0x2d, 0x25, 0xc7, 0x97, 0x11, 0x53, 0x12, 0x49,
    0xe1, 0x12, 0x96, 0x28, 0x04, 0x2d, 0xbb, 0xb6, 0xc1, 0x20, 0xd1, 0x44,
    0x35, 0x24, 0xef, 0x4c, 0x0e, 0x6e, 0x1d, 0x89, 0x56, 0xee, 0xb2, 0x07,
    0x7a, 0xf1, 0x23, 0x49, 0xdd, 0xee, 0xe5, 0x44, 0x83, 0xbc, 0x06, 0xc2,
    0xc6, 0x19, 0x48, 0xcd, 0x02, 0xb2, 0x02, 0xe7, 0x96, 0xae, 0xbd, 0x94,
    0xd3, 0xa7, 0xcb, 0xf8, 0x59, 0xc2, 0xc1, 0x81, 0x9c, 0x32, 0x4c, 0xb8,
    0x2b, 0x9c, 0xd3, 0x4e, 0xde, 0x26, 0x3a, 0x2a, 0xbf, 0xfe, 0x47, 0x33,
    0xf0, 0x77, 0x86, 0x9e, 0x86, 0x60, 0xf7, 0xd6, 0x83, 0x4d, 0xa5, 0x3d,
    0x69, 0x0e, 0xf7, 0x98, 0x5f, 0x6b, 0xc3, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x81, 0x81, 0x00, 0x87, 0x4b, 0xf0, 0xff, 0xc2, 0xf2, 0xa7, 0x1d,
    0x14, 0x67, 0x1d, 0xdd, 0x01, 0x71, 0xc9, 0x54, 0xd7, 0xfd, 0xbf, 0x50,
    0x28, 0x1e, 0x4f, 0x6d, 0x99, 0xea, 0x0e, 0x1e, 0xbc, 0xf8, 0x2f, 0xaa,
    0x58, 0xe7, 0xb5, 0x95, 0xff, 0xb2, 0x93, 0xd1, 0xab, 0xe1, 0x7f, 0x11,
    0x0b, 0x37, 0xc4, 0x8c, 0xc0, 0xf3, 0x6c, 0x37, 0xe8, 0x4d, 0x87, 0x66,
    0x21, 0xd3, 0x27, 0xf6, 0x4b, 0xbe, 0x08, 0x45, 0x7d, 0x3e, 0xc4, 0x09,
    0x8b, 0xa2, 0xfa, 0x0a, 0x31, 0x9f, 0xba, 0x41, 0x1c, 0x28, 0x41, 0xed,
    0x7b, 0xe8, 0x31, 0x96, 0xa8, 0xcd, 0xf9, 0xda, 0xa5, 0xd0, 0x06, 0x94,
    0xbc, 0x33, 0x5f, 0xc4, 0xc3, 0x22, 0x17, 0xfe, 0x04, 0x88, 0xbc, 0xe9,
    0xcb, 0x72, 0x02, 0xe5, 0x94, 0x68, 0xb1, 0xea, 0xd1, 0x19, 0x00, 0x04,
    0x77, 0xdb, 0x2c, 0xa7, 0x97, 0xfa, 0xc1, 0x9e, 0xda, 0x3f, 0x58, 0xc1,
    0x02, 0x41, 0x00, 0xe2, 0xab, 0x76, 0x08, 0x41, 0xbb, 0x9d, 0x30, 0xa8,
    0x1d, 0x22, 0x2d, 0xe1, 0xeb, 0x73, 0x81, 0xd8, 0x22, 0x14, 0x40, 0x7f,
    0x1b, 0x97, 0x5c, 0xbb, 0xfe, 0x4e, 0x1a, 0x94, 0x67, 0xfd, 0x98, 0xad,
    0xbd, 0x78, 0xf6, 0x07, 0x83, 0x6c, 0xa5, 0xbe, 0x19, 0x28, 0xb9, 0xd1,
    0x60, 0xd9, 0x7f, 0xd4, 0x5c, 0x12, 0xd6, 0xb5, 0x2e, 0x2c, 0x98, 0x71,
    0xa1, 0x74, 0xc6, 0x6b, 0x48, 0x81, 0x13, 0x02, 0x41, 0x00, 0xc5, 0xab,
    0x27, 0x60, 0x21, 0x59, 0xae, 0x7d, 0x6f, 0x20, 0xc3, 0xc2, 0xee, 0x85,
    0x1e, 0x46, 0xdc, 0x11, 0x2e, 0x68, 0x9e, 0x28, 0xd5, 0xfc, 0xbb, 0xf9,
    0x90, 0xa9, 0x9e, 0xf8, 0xa9, 0x0b, 0x8b, 0xb4, 0x4f, 0xd3, 0x64, 0x67,
    0xe7, 0xfc, 0x17, 0x89, 0xce, 0xb6, 0x63, 0xab, 0xda, 0x33, 0x86, 0x52,
    0xc3, 0xc7, 0x3f, 0x11, 0x17, 0x74, 0x90, 0x2e, 0x84, 0x05, 0x65, 0x92,
    0x70, 0x91, 0x02, 0x41, 0x00, 0xb6, 0xcd, 0xbd, 0x35, 0x4f, 0x7d, 0xf5,
    0x79, 0xa6, 0x3b, 0x48, 0xb3, 0x64, 0x3e, 0x35, 0x3b, 0x84, 0x89, 0x87,
    0x77, 0xb4, 0x8b, 0x15, 0xf9, 0x4e, 0x0b, 0xfc, 0x05, 0x67, 0xa6, 0xae,
    0x59, 0x11, 0xd5, 0x7a, 0xd6, 0x40, 0x9c, 0xf7, 0x64, 0x7b, 0xf9, 0x62,
    0x64, 0xe9, 0xbd, 0x87, 0xeb, 0x95, 0xe2, 0x63, 0xb7, 0x11, 0x0b, 0x9a,
    0x1f, 0x9f, 0x94, 0xac, 0xce, 0xd0, 0xfa, 0xfa, 0x4d, 0x02, 0x40, 0x71,
    0x19, 0x5e, 0xec, 0x37, 0xe8, 0xd2, 0x57, 0xde, 0xcf, 0xc6, 0x72, 0xb0,
    0x7a, 0xe6, 0x39, 0xf1, 0x0c, 0xbb, 0x9b, 0x0c, 0x73, 0x9d, 0x0c, 0x80,
    0x99, 0x68, 0xd6, 0x44, 0xa9, 0x4e, 0x3f, 0xd6, 0xed, 0x92, 0x87, 0x07,
    0x7a, 0x14, 0x58, 0x3f, 0x37, 0x90, 0x58, 0xf7, 0x6a, 0x8a, 0xec, 0xd4,
    0x3c, 0x62, 0xdc, 0x8c, 0x0f, 0x41, 0x76, 0x66, 0x50, 0xd7, 0x25, 0x27,
    0x5a, 0xc4, 0xa1, 0x02, 0x41, 0x00, 0xbb, 0x32, 0xd1, 0x33, 0xed, 0xc2,
    0xe0, 0x48, 0xd4, 0x63, 0x38, 0x8b, 0x7b, 0xe9, 0xcb, 0x4b, 0xe2, 0x9f,
    0x4b, 0x62, 0x50, 0xbe, 0x60, 0x3e, 0x70, 0xe3, 0x64, 0x75, 0x01, 0xc9,
    0x7d, 0xdd, 0xe2, 0x0a, 0x4e, 0x71, 0xbe, 0x95, 0xfd, 0x5e, 0x71, 0x78,
    0x4e, 0x25, 0xac, 0xa4, 0xba, 0xf2, 0x5b, 0xe5, 0x73, 0x8a, 0xae, 0x59,
    0xbb, 0xfe, 0x1c, 0x99, 0x77, 0x81, 0x44, 0x7a, 0x2b, 0x24,
};

static const uint8_t ECC_KEY[] =
{
    0x49, 0xc9, 0xa8, 0xc1, 0x8c, 0x4b, 0x88, 0x56,
    0x38, 0xc4, 0x31, 0xcf, 0x1d, 0xf1, 0xc9, 0x94,
    0x13, 0x16, 0x09, 0xb5, 0x80, 0xd4, 0xfd, 0x43,
    0xa0, 0xca, 0xb1, 0x7d, 0xb2, 0xf1, 0x3e, 0xee
};

int main( void )
{
    ASSERT( psa_crypto_init( ) == PSA_SUCCESS );
    sign_a_message_using_ecdsa(ECC_KEY, sizeof(ECC_KEY));
    cipher_examples( );
exit:
    mbedtls_psa_crypto_free( );
    return( 0 );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC &&
          MBEDTLS_CIPHER_MODE_CTR && MBEDTLS_CIPHER_MODE_WITH_PADDING */
