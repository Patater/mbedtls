/*
 *  MbedTLS SSL context deserializer from base64 code
 *
 *  Copyright (C) 2006-2020, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "mbedtls/error.h"
#include "mbedtls/base64.h"

/*
 * This program version
 */
#define PROG_NAME "ssl_base64_dump"
#define VER_MAJOR 0
#define VER_MINOR 1

/*
 * Global values
 */
FILE *b64_file = NULL;      /* file with base64 codes to deserialize */
char debug = 0;             /* flag for debug messages */

/*
 * Basic printing functions
 */
void print_version( )
{
    printf( "%s v%d.%d\n", PROG_NAME, VER_MAJOR, VER_MINOR );
}

void print_usage( )
{
    print_version();
    printf(
        "Usage:\n"
        "\t-f path - Path to the file with base64 code\n"
        "\t-v      - Show version\n"
        "\t-h      - Show this usage\n"
        "\t-d      - Print more information\n"
        "\n"
    );
}

void printf_dbg( const char *str, ... )
{
    if( debug )
    {
        va_list args;
        va_start( args, str );
        printf( "debug: " );
        vprintf( str, args );
        fflush( stdout );
        va_end( args );
    }
}

void printf_err( const char *str, ... )
{
    va_list args;
    va_start( args, str );
    fprintf( stderr, "ERROR: " );
    vfprintf( stderr, str, args );
    fflush( stderr );
    va_end( args );
}

/*
 * Exit from the program in case of error
 */
void error_exit()
{
    if( NULL != b64_file )
    {
        fclose( b64_file );
    }
    exit( -1 );
}

/*
 * This function takes the input arguments of this program
 */
void parse_arguments( int argc, char *argv[] )
{
    int i = 1;

    if( argc < 2 )
    {
        print_usage();
        error_exit();
    }

    while( i < argc )
    {
        if( strcmp( argv[i], "-d" ) == 0 )
        {
            debug = 1;
        }
        else if( strcmp( argv[i], "-h" ) == 0 )
        {
            print_usage();
        }
        else if( strcmp( argv[i], "-v" ) == 0 )
        {
            print_version();
        }
        else if( strcmp( argv[i], "-f" ) == 0 )
        {
            if( ++i >= argc )
            {
                printf_err( "File path is empty\n" );
                error_exit();
            }

            if( ( b64_file = fopen( argv[i], "r" ) ) == NULL )
            {
                printf_err( "Cannot find file \"%s\"\n", argv[i] );
                error_exit();
            }
        }
        else
        {
            print_usage();
            error_exit();
        }

        i++;
    }
}

/*
 * This function prints base64 code to the stdout
 */
void print_b64( const unsigned char *b, size_t len )
{
    size_t i = 0;
    const unsigned char *end = b + len;
    printf("\t");
    while( b < end )
    {
        if( ++i > 75 )
        {
            printf( "\n\t" );
            i = 0;
        }
        printf( "%c", *b++ );
    }
    printf( "\n" );
    fflush( stdout );
}

/*
 * This function prints hex code from the buffer to the stdout.
 */
void print_hex( const unsigned char *b, size_t len )
{
    size_t i = 0;
    const unsigned char *end = b + len;
    printf("\t");
    while( b < end )
    {
        printf( "%02X ", (unsigned char) *b++ );
            if( ++i > 25 )
        {
            printf("\n\t");
            i = 0;
        }
    }
    printf("\n");
    fflush(stdout);
}

/*
 * Read next base64 code from the 'b64_file'. The 'b64_file' must be opened
 * previously. After each call to this function, the internal file position
 * indicator of the global b64_file is advanced.
 *
 * /p b64       buffer for input data
 * /p max_len   the maximum number of bytes to write
 *
 * \retval      number of bytes written in to the b64 buffer or 0 in case no more
 *              data was found
 */
size_t read_next_b64_code( unsigned char *b64, size_t max_len )
{
    size_t len = 0;
    uint32_t missed = 0;
    char pad = 0;
    char c = 0;

    while( EOF != c )
    {
        char c_valid = 0;

        c = (char) fgetc( b64_file );

        if( pad == 1 )
        {
            if( c == '=' )
            {
                c_valid = 1;
                pad = 2;
            }
        }
        else if( ( c >= 'A' && c <= 'Z' ) ||
                 ( c >= 'a' && c <= 'z' ) ||
                 ( c >= '0' && c <= '9' ) ||
                   c == '+' || c == '/' )
        {
            c_valid = 1;
        }
        else if( c == '=' )
        {
            c_valid = 1;
            pad = 1;
        }
        else if( c == '-' )
        {
            c = '+';
            c_valid = 1;
        }
        else if( c == '_' )
        {
            c = '/';
            c_valid = 1;
        }

        if( c_valid )
        {
            if( len < max_len )
            {
                b64[ len++ ] = c;
            }
            else
            {
                missed++;
            }
        }
        else if( len > 0 )
        {
            if( missed > 0 )
            {
                printf_err( "Buffer for the base64 code is too small. Missed %u characters\n", missed );
            }
            return len;
        }
    }

    printf_dbg( "End of file\n" );
    return 0;
}

int main( int argc, char *argv[] )
{
    enum { B64BUF_LEN = 4 * 1024 };
    enum { SSLBUF_LEN = B64BUF_LEN * 3 / 4 + 1 };

    unsigned char b64[ B64BUF_LEN ];
    unsigned char ssl[ SSLBUF_LEN ];
    uint32_t b64_counter = 0;

    parse_arguments( argc, argv );

    while( NULL != b64_file )
    {
        size_t ssl_len;
        size_t b64_len = read_next_b64_code( b64, B64BUF_LEN );
        if( b64_len > 0)
        {
            int ret;

            b64_counter++;

            if( debug )
            {
                printf( "%u. Base64 code:\n", b64_counter );
                print_b64( b64, b64_len );
            }

            ret = mbedtls_base64_decode( ssl, SSLBUF_LEN, &ssl_len, b64, b64_len );
            if( ret != 0)
            {
                mbedtls_strerror( ret, (char*) b64, B64BUF_LEN );
                printf_err( "base64 code cannot be decoded - %s\n", b64 );
                continue;
            }

            if( debug )
            {
                printf( "\n   Decoded data in hex:\n");
                print_hex( ssl, ssl_len );
            }

            /* TODO: deserializing */

            printf( "\n" );
        }
        else
        {
            fclose( b64_file );
            b64_file = NULL;
        }
    }

    printf( "Finish. Found %u base64 codes\n", b64_counter );

    return 0;
}
