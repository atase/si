#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
 
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define PORT 7775

unsigned char key3[17] = "WnZq4t7w!z%C*F-J\0";
unsigned char iv3[17] = "8377736377728273\0";


unsigned char key[100];
int key_length;
unsigned char iv[100];
int iv_length;


int client_socket;
struct sockaddr_in address;

char buffer[1024];
int buffer_length;


char client_name[10];
char crypto_method[10];
char client_key[17];
char action[15];
int name_validation = 0;

int client_code;

int mb_length, ma_length;
int mb_method, ma_method;

char *data;
int data_length;

char crypt_data[1024];
int no_blocks;



void handleErrors(void);
int decryptDataLibrary(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int encryptDataCBC(unsigned char *plaintext, unsigned char *key, unsigned char *iv);
int encryptDataCFB(unsigned char *plaintext, unsigned char *key, unsigned char *iv);
int decryptDataCBC(unsigned char *cryptotext, unsigned char *key, unsigned char *iv);
int decryptDataCFB(unsigned char *cryptotext, unsigned char *key, unsigned char *iv);


void main(int argc, char *argv[]){
    
    
    printf("[Client] Hello from client.\n");

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(client_socket == -1){
        perror("[!!!] Fail to create socket!\n");
        exit(EXIT_FAILURE);
    }
    printf("[Client] Client socket: %d.\n", client_socket);
    bzero(&address, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(PORT);
 
    if(connect(client_socket, (struct sockaddr*)&address, sizeof(address)) != 0){
        perror("[!!!] Fail to connect to the server!\n");
        exit(EXIT_FAILURE);
    }
    
    printf("[+] Connected to the server.\n");

    read(client_socket, &client_code, sizeof(int));


    if(client_code == 0){

        
        FILE *fp = fopen("data.txt", "r");
        char *filedata;
        long numbytes;
        if(fp == NULL){
            return -1;
        }
        fseek(fp, 0L, SEEK_END);
        numbytes = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        filedata = (char*)calloc(numbytes, sizeof(char));

        if(filedata == NULL){
            return -1;
        }

        fread(filedata, sizeof(char), numbytes, fp);
        fclose(fp);

        memset(buffer, '\0', sizeof(buffer));
        printf("[info] You are client A. Choose a crypto method!\n");
        while(1){
            printf("[info] Crypto method (CBC/CFB): ");
            scanf("%s", crypto_method);

            if(send(client_socket, &crypto_method, strlen(crypto_method), 0) != strlen(crypto_method)){
                perror("[!!!] Fail to send client name to key manager.\n");
                exit(EXIT_FAILURE);
            }

            if(read(client_socket, &buffer, sizeof(buffer)) == 0){
                perror("[!!!] Fail to read KM confirmation for crypto method.\n");
                exit(EXIT_FAILURE);
            }else{
                if(strcmp(buffer, "KM0") == 0){
                    printf("[KM] Crypto method incorrect! Choose again! (CBC/CFB).\n");
                }else{
                    printf("[KM] Crypto method is oke! You are using %s.\n", crypto_method);
                    break;
                }
            }
        }
        printf("[info] Data from file: %s", filedata);
        data = (char*)calloc(numbytes, sizeof(char));
        strcpy(data, filedata);
        memset(buffer, '\0', sizeof(buffer));
        read(client_socket, &buffer_length, sizeof(int));
        read(client_socket, buffer, buffer_length);
        printf("[KM] Encrypted key:\n");
        BIO_dump_fp(stdout, (const char*) buffer, buffer_length);

        memset(key, '\0', sizeof(key));
        key_length = decryptDataLibrary(buffer, buffer_length, key3, iv3, key);
        key[key_length] = '\0';
        printf("[info] Decrypted key for A: %s\n", key);


        memset(buffer, '\0', sizeof(buffer));
        read(client_socket, &buffer_length, sizeof(int));
        read(client_socket, buffer, buffer_length);
        printf("[KM] Encrypted iv:\n");
        BIO_dump_fp(stdout, (const char*) buffer, buffer_length);

        memset(iv, '\0', sizeof(iv));
        iv_length = decryptDataLibrary(buffer, buffer_length, key3, iv3, iv);
        iv[iv_length] = '\0';
        printf("[info] Decrypted iv for A: %s\n", iv);

        printf("[info] Encrypt data with key %s and iv %s.\n", key, iv);
        int crypt_data_length;
        if(strcmp(crypto_method, "CBC") == 0){
            crypt_data_length = encryptDataCBC(data, key, iv);
        }else{
            crypt_data_length = encryptDataCFB(data, key, iv);
        }

        printf("\n[info] Send number of blocks to KM.\n");
        send(client_socket, &no_blocks, sizeof(int), 0);
        printf("[info] Send encrypted data to KM.\n");
        int block_hexdec_length = 32;
        char block_hex[33];
        memset(block_hex, '\0', sizeof(block_hex));
        printf("[info] Full length data: %d.\n", crypt_data_length);
        for(int i=0;i<=crypt_data_length;i++){
            if(i%32 == 0 && i != 0){
                send(client_socket, &block_hexdec_length, sizeof(int), 0);
                send(client_socket, &block_hex, block_hexdec_length, 0);
            }
            block_hex[i%32] = crypt_data[i];
        }

        printf("\n");

        memset(buffer, '\0', sizeof(buffer));
        read(client_socket, &buffer, sizeof(buffer));
        if(strcmp(buffer, "KM1") == 0){
            printf("[info] B has received all data.\n");
        }else{
            printf("[info] Something went wrong while sending data to B...\n");
        }

    }
    else{
        int code = 0;
        memset(buffer, '\0', sizeof(buffer));
        printf("[info] You are client B. Wait data from KM.\n");
        read(client_socket, &mb_method, sizeof(int));

        if(mb_method == 0){
            printf("[info] You are using crypto method - CBC.\n");
        }else{
            printf("[info] You are using crypto method - CFB.\n");
        }
        read(client_socket, &buffer_length, sizeof(int));
        read(client_socket, buffer, buffer_length);
        printf("[KM] Encrypted key:\n");
        BIO_dump_fp(stdout, (const char*) buffer, buffer_length);

        memset(key, '\0', sizeof(key));
        key_length = decryptDataLibrary(buffer, buffer_length, key3, iv3, key);
        printf("[info] Decrypted key for B: %s\n", key);


        read(client_socket, &buffer_length, sizeof(int));
        read(client_socket, buffer, buffer_length);
        printf("[KM] Encrypted iv:\n");
        BIO_dump_fp(stdout, (const char*) buffer, buffer_length);

        memset(iv, '\0', sizeof(iv));
        iv_length = decryptDataLibrary(buffer, buffer_length, key3, iv3, iv);
        printf("[info] Decrypted iv for B: %s\n", iv);


        printf("[info] Wait number of blocks from KM.\n");
        read(client_socket, &no_blocks, sizeof(int));
        
        int block_length;
        char full_data[1024];
        memset(full_data, '\0', sizeof(full_data));
        memset(buffer, '\0', sizeof(buffer));
        printf("[info] There are %d number of blocks. Receiving data...\n", no_blocks);
        for(int i=0;i<no_blocks;i++){
            read(client_socket, &block_length, sizeof(int));
            read(client_socket, buffer, block_length);
            printf("\n[KM - data] %s", buffer);
            strncat(full_data, buffer, strlen(buffer));
        }
        printf("\n\n[info] Decrypt data received...\n");
        if(mb_method == 0){
            decryptDataCBC(full_data, key, iv);
        }else{
            decryptDataCFB(full_data, key, iv);
        }

        printf("\n\n[info] Delete padding...\n");
        int padding = crypt_data[strlen(crypt_data)-1] - '0';
        printf("[info] Padding: %d\n", padding);
        for(int i=0;i<=padding;i++){
            crypt_data[strlen(crypt_data) - 1] = '\0';
        }
        printf("\n[info] Final data: %s\n", crypt_data);

        code = 1;

        send(client_socket, &code, sizeof(int), 0);

    }

    close(client_socket);
    return ;
}

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int decryptDataLibrary(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext){

    EVP_CIPHER_CTX *ctx;
    int length;
    int plaintext_length;

    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1){
        handleErrors();
    }

    if(EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len) != 1){
        handleErrors();
    }

    plaintext_length = length;

    if(EVP_DecryptFinal_ex(ctx, plaintext + length, &length) != 1){
        handleErrors();
    }
    plaintext_length += length;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_length;

}


int encryptDataCBC(unsigned char *plaintext, unsigned char *key, unsigned char *iv){
    printf("\n\n[***] CBC Encryption...\n\n");

    char plain_data[1024];

    memset(crypt_data, '\0', sizeof(crypt_data));
    memset(plain_data, '\0', sizeof(plain_data));

    strcpy(plain_data, plaintext);

    int padding = strlen(plain_data) % 16;
    int data_length = strlen(plain_data);

    printf("[info] Text length: %d", strlen(plain_data));
    if(padding != 0){
        padding = 16 - padding;
        printf("\n[info] Padding: %d\n", padding);
        for(int i=0;i<padding-1; i++){
            char c = i + '0';
            plain_data[data_length + i] = c;
        }
        plain_data[strlen(plain_data)] = (padding-1) + '0';
    }

    printf("%s\n", plain_data);
    int index = 0, block = 1, block_length = 16;
    int v_index = 0;
    char cryptotext[1024];
    char iv_crypt[17];

    memset(iv_crypt, '\0', sizeof(iv_crypt));
    strcpy(iv_crypt, iv);
    memset(cryptotext, '\0', sizeof(cryptotext));

    printf("\n[info] IV: ");
    for(int i=0;i<strlen(iv_crypt);i++){
        printf("%02X ", iv_crypt[i]);
    }

    while(index < strlen(plain_data)){
        if(index % 16 == 0){
            cryptotext[index] = plain_data[index]^(*(iv_crypt + (index%16)));
            cryptotext[index] = cryptotext[index]^(*(key + (index%16)));
            if(index != 0){
                printf("\n[info] New iv:");
                for(int i=index-16, j=0;i<index;i++, j++){
                    printf("%02X ", cryptotext[i]);
                    iv_crypt[j] = cryptotext[i];
                }
            }
            printf("\n[info] Block %d: ", block);
            block++;
        }
        cryptotext[index] = plain_data[index]^(*(iv_crypt + (index%16)));
        cryptotext[index] = cryptotext[index]^(*(key + (index%16)));
        printf("%02X ", cryptotext[index]);
        sprintf(crypt_data + v_index, "%02X", cryptotext[index]);
        v_index += 2;
        index++;
    }

    no_blocks = block-1;
    return strlen(crypt_data);
}

int encryptDataCFB(unsigned char *plaintext, unsigned char *key, unsigned char *iv){
    
    printf("\n\n[***] CFB Encryption...\n\n");
    char plain_data[1024];

    memset(crypt_data, '\0', sizeof(crypt_data));
    memset(plain_data, '\0', sizeof(plain_data));
    strcpy(plain_data, plaintext);

    int padding = strlen(plain_data) % 16;
    int data_length = strlen(plain_data);

    if(padding != 0){
        padding = 16 - padding;
        printf("[info] Padding: %d\n", padding);
        for(int i=0;i<padding-1; i++){
            char c = i + '0';
            plain_data[data_length + i] = c;
        }
        plain_data[strlen(plain_data)] = (padding-1) + '0';
    }

    printf("%s\n", plain_data);

    int index = 0, block = 1, iv_index = 0, block_length = 16;
    char cryptotext[1024];
    char iv_crypt[17];
    char iv_crypt_backup[17];
    char crt[17];
    int v_index = 0;

    memset(iv_crypt, '\0', sizeof(iv_crypt));
    memset(crt, '\0', sizeof(crt));
    memset(iv_crypt_backup, '\0', sizeof(iv_crypt_backup));
    strcpy(iv_crypt, iv);
    strcpy(iv_crypt_backup, iv);
    memset(cryptotext, '\0', sizeof(cryptotext));
    printf("\n[info] IV: ");
    
    for(int i=0;i<strlen(iv_crypt);i++){
        printf("%02X ", iv_crypt[i]);
    }

    while(index < strlen(plain_data)){
        if(index% 16 == 0){
            char c = iv_crypt[index%16] ^ key[index%16];
            cryptotext[index] = plain_data[index] ^ c;
            if(index != 0){
                for(int i=index-16, k=0;i<index;i++, k++){
                    iv_crypt[k] = cryptotext[i];
                }
                printf("\n[info] New iv: ");
                for(int i=0;i<strlen(iv_crypt);i++){
                    printf("%02X ", iv_crypt[i]);
                }

            }
            printf("\n[info] Block %d: ", block);
            block++;
        }
        char c = iv_crypt[index%16] ^ key[index%16];
        cryptotext[index] = plain_data[index] ^ c;
        printf("%02X ", cryptotext[index]);
        sprintf(crypt_data + v_index, "%02X", cryptotext[index]);
        v_index += 2;
        index++;
    }
    no_blocks = block-1;
    return strlen(crypt_data);
}


int decryptDataCBC(unsigned char *cryptotext, unsigned char *key, unsigned char *iv){
    char iv_crypt[17];

    memset(iv_crypt, '\0', sizeof(iv_crypt));
    strcpy(iv_crypt, iv);
    iv_crypt[strlen(iv_crypt)] = '\0';

    printf("\n[info] CBC Decrypt...\n");
    int blocks = 1;
    char hexdec[3]="00";
    int iv_index = 0;
    char ch[1024];
    memset(ch, '\0', sizeof(iv_crypt));

    for(int i=0;i<strlen(cryptotext);i+=2){
        if(i%32 == 0){
            blocks++;
            //printf("\n[info] New IV: ");
            if(i!=0){
                for(int j=iv_index-16,k=0;j<iv_index;j++,k++){
                    iv_crypt[k] = ch[j];
                    //printf("%02X ", ch[j]);
                }
            }
            //printf("\nBlock %d: ",blocks);
        }
        hexdec[0] = cryptotext[i];
        hexdec[1] = cryptotext[i +1];
        hexdec[2] = '\0';
        ch[iv_index] = strtoul(hexdec, NULL, 16);
        char c = (*(key + (iv_index%16)))^ch[iv_index];
        crypt_data[iv_index] = c^iv_crypt[iv_index%16];
        printf("%c" ,crypt_data[iv_index]);

        iv_index++;

    }

    printf("\n");

    return 0;
}

int decryptDataCFB(unsigned char *cryptotext, unsigned char *key, unsigned char *iv){

    char plaintext[1024];
    memset(plaintext, '\0', sizeof(plaintext));
    int block = 1;
    
    char hexdec[3]="00";
    int index = 0;
    char ch[1024];
    char ck[1024];
    char iv_crypt[17];
    memset(iv_crypt, '\0', sizeof(iv_crypt));
    strcpy(iv_crypt, iv);
    memset(ck, '\0', sizeof(ck));
    memset(ch, '\0', sizeof(ch));

    printf("\n[info] Data to decrypt: ");
    for(int i=0;i<strlen(cryptotext);i++){
        printf("%c ", cryptotext[i]);
    }

    printf("\n[info] CFB Decryption...\n");



    for(int i=0;i<strlen(cryptotext);i+=2){
        if(i%32 == 0){
            if(i != 0){

                //printf("\n[info] New IV:");
                for(int j=index-16, k=0;j < index; j++,k++){
                    iv_crypt[k] = ch[j];
                    //printf("%02X", iv_crypt[k]);
                }
            } 
            //printf("\n[info] Block %d: ", block);
            block++;

        }
        hexdec[0] = cryptotext[i];
        hexdec[1] = cryptotext[i +1];
        ch[index] = strtoul(hexdec, NULL, 16);
        ck[index] = key[index%16]^iv_crypt[index%16];
        crypt_data[index] = ch[index] ^ ck[index];
        printf("%c", crypt_data[index]);
        index++;


    }

    printf("\n");

    return 0;
}