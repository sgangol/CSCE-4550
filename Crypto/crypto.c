/*      AUTHOR:       Srizan Gangol   
		For Educational purpose ONLY!
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <assert.h>


int main(void) {
    unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; //iv has to be the same length as the block: 128 bits block.
    char plaintext[] = "This is a top secret.";
    unsigned char * og_cipher = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
    unsigned char outbuf[1024];
    int outl, templen;
    EVP_CIPHER_CTX * ctx;
    FILE * out;
    FILE * fp;
    FILE * fp2;
    char * outfile;
    char * input;
    char * line = NULL;
    int broken = 0;
    size_t len = 0;
    ssize_t read;
    char * str;
    int i = 0, j = 0;
    int length;
    unsigned char * key;
    int ciphertext_len = 0;
    unsigned char * ciphertext;
    unsigned char * final_ciphertext;


    input = (char *) malloc(15 * sizeof(char));
    key = (unsigned char *) malloc(16 * sizeof(unsigned char));

    input = "words.txt";
    fp = fopen(input, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
 
    assert(strlen(plaintext) == 21);

   while ((read = getline(&line, &len, fp)) != -1) {
        ciphertext = (unsigned char *) malloc(1024 * sizeof(unsigned char));
        final_ciphertext = (unsigned char *) malloc(1024 * sizeof(unsigned char));

        if (read >= 16) //dismiss this word if it is longer than 16 characters
            continue;

       else {
           length = strlen(line);

            strcpy(key,line);
            for (i = length-1 ; i < 16 ; ++i) //padding spaces at the end
                key[i] = ' ';

//            printf("key: >%s<\n", key);

            /* Encryption */
            ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
            if(!EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, strlen(plaintext)))
                 exit(EXIT_FAILURE);

            ciphertext_len = outl;

            if(!EVP_EncryptFinal_ex(ctx, ciphertext + outl, &outl)) //outbuf+outl to avoid overwritting from Update
                 exit(EXIT_FAILURE);

            ciphertext_len += outl;

//            printf("strlen = %d\n", strlen(ciphertext));

            if (strlen(ciphertext) != 0) {

                for(i = 0; i < strlen(ciphertext) ; i++) //converting string to hex
                    sprintf(final_ciphertext+i*2, "%02x", ciphertext[i]);

//                printf("final_ciphertext: >%s<\n", final_ciphertext);

     
                if (!strcmp(final_ciphertext, og_cipher)) {
                    printf("\nKey Found\n");
                    printf("Key: \"%s\"\n", key);
                    printf("ciphertext: \"%s\"\n\n", final_ciphertext);
                    exit(0);
                }
            }
            EVP_CIPHER_CTX_free(ctx);
        }

       if (ciphertext)
           free(ciphertext);
       if (final_ciphertext)
           free(final_ciphertext);
    }

    if (str)
        free(str);
    if (line)
        free(line);
    if (key)
        free(key);

    fclose(fp);


    return 0;
}




   /* 
    outfile = (char *) malloc(7 * sizeof(char));
    outfile = "output";
    out = fopen(outfile, "wb");
    fwrite(outbuf, 1, outl, out);
    fclose(out);
                printf("ciphertext: ");
                for (i = 0 ; i < strlen(ciphertext)-1 ; ++i)
                    printf("%02x", ciphertext[i]);
                printf("\n\n");
    */
