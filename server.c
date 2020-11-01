#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>



#define MAX_CLIENTS 2
#define PORT 7775
#define CNC 3

int server_socket,  clients[MAX_CLIENTS];
int client_index;
int client_socket;

int address_length;
struct sockaddr_in  address;

char buffer[1024];
unsigned char message[1024];
int message_length;
int buffer_length;
char crypt_data[1024];
char decrypt_data[1024];
int no_blocks;
int no_blocks_received;
int methods[2];

unsigned char* decrypt_dataB;

int p[2];
int r[2];
int m[2];


unsigned char key1[17] = "$B&E)H@McQfTjWnZ\0";
unsigned char key2[17] = "p3s6v9y$B&E)H@Mb\0";
unsigned char key3[17] = "WnZq4t7w!z%C*F-J\0";

unsigned char iv1[17] = "1234567891234567\0";
unsigned char iv2[17] = "9876543219876543\0";
unsigned char iv3[17] = "8377736377728273\0";

int encryptDataLibrary(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int encryptDataCBC(unsigned char *plaintext, unsigned char *key, unsigned char *iv);
int encryptDataCFB(unsigned char *plaintext, unsigned char *key, unsigned char *iv);
int decryptDataCBC(unsigned char *cryptotext, unsigned char *key, unsigned char *iv);
int decryptDataCFB(unsigned char *cryptotext, unsigned char *key, unsigned char *iv);


void main(int arc, char* argv[]){
    pipe(p);
    pipe(m);
    for(int i=0;i<MAX_CLIENTS;i++){
        clients[i] = 0;
    }

    if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        perror("[!!!] Fail to create server socket!");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
        perror("[!!!] Fail to initialize socket options!");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);



    if(bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0){
        perror("[!!!] Fail to bind the name to socket!");
        exit(EXIT_FAILURE);
    }

    printf("[+] Listener on port %d.\n", PORT);
    
    if(listen(server_socket, 2) < 0){
        perror("[!!!] Fail to listen 2 incomming connections.\n");
        exit(EXIT_FAILURE);
    }


    address_length = sizeof(address);

    printf("[+] Waiting for 2 connections...\n");


    while(client_index < 2){
        address_length = sizeof(address);
        if((clients[client_index] = accept(server_socket, (struct sockaddr*)&address, (socklen_t*)&address_length)) < 0){
            perror("[!!!] Fail to accept client!");
            exit(EXIT_FAILURE);
        }else{
            printf("[+] Client connected -> socket: %d, ip: %s, port: %d.\n", clients[client_index], inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            send(clients[client_index], &client_index, sizeof(int),0);
            client_index++;
        }
    }

    printf("[info] Both clients are connected. Begin process...\n");
    if(fork() == 0){
        // parent process - A
        buffer[buffer_length] = '\0';
        
        memset(message, '\0', sizeof(message));

        if(read(clients[0], buffer, sizeof(buffer)) != 0){
                    
            if(strcmp(buffer, "CBC") != 0 && strcmp(buffer, "CFB") != 0){
                strcpy(message, "KM0");
            }else{
                strcpy(message, "KM1");
                                    
                if(strcmp(buffer, "CBC") == 0){
                    methods[0] = 0;
                    methods[1] = 1;
                }else{
                    methods[0] = 1;
                    methods[1] = 0;
                }
            }
            
            if(send(clients[0], message, strlen(message), 0) == 0){
                perror("[!!!] Fail to send confirmation to client A!\n");
                exit(EXIT_FAILURE);
            }else{
                printf("[info] Method confirmation was sent to client A.\n");
            }
        }
        
        close(m[0]);
        write(m[1], &methods[1], sizeof(int));
        close(m[1]);

        memset(message, '\0', sizeof(message));
        message_length = encryptDataLibrary(key1, strlen(key1), key3, iv3, message);
        printf("\n[KM] Crypto text for keyA:\n");
        BIO_dump_fp(stdout, (const char*) message, message_length);

        if(send(clients[0], &message_length, sizeof(int), 0) == 0){
            perror("[!!!] Fail to send encrypted key length to client A!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted key length was sent to client A.\n");
        }

        if(send(clients[0], &message, strlen(message), 0) == 0){
            perror("[!!!] Fail to send encrypted key to client A!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted key was sent to client A.\n");
        }

        memset(message, '\0', sizeof(message));
        message_length = encryptDataLibrary(iv1, strlen(iv1), key3, iv3, message);
        printf("\n[KM] Crypto text for ivA:\n");
        BIO_dump_fp(stdout, (const char*) message, message_length);

        if(send(clients[0], &message_length, sizeof(int), 0) == 0){
            perror("[!!!] Fail to send encrypted key length to client A!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted iv length was sent to client A.\n");
        }

        if(send(clients[0], &message, strlen(message), 0) == 0){
            perror("[!!!] Fail to send encrypted iv to client A!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted iv was sent to client A.\n");
        }


        printf("[info] Wait number of blocks from client A.\n");
        read(clients[0], &no_blocks_received, sizeof(int));
        printf("[info] Number of blocks: %d. Receiving data....\n", no_blocks_received);

        int block_length;

        for(int i=0;i<no_blocks_received;i++){
            read(clients[0], &block_length, sizeof(int));
            read(clients[0], buffer, block_length);
            strncat(decrypt_data, buffer, strlen(buffer));
        }
        int decryptlength = 7;
        if(methods[0] == 0){
            decryptlength = decryptDataCBC((unsigned char*)decrypt_data, key1, iv1);
            printf("\n[-------]%d\n", decryptlength);
        }else{
            decryptlength = decryptDataCFB((unsigned char*)decrypt_data, key1, iv1);
            printf("\n[-------]%d\n", decryptlength);
        }

        printf("\n[Crypto-text] %s\n", decrypt_data);
        printf("\n[Plain data] %s\n", decrypt_dataB);


        close(p[0]);
        write(p[1], &decryptlength, sizeof(int));
        write(p[1], decrypt_dataB, decryptlength);
        close(p[1]);

        int code;

        close(r[1]);
        read(r[0], &code, sizeof(int));
        close(r[0]);

        memset(message, '\0', sizeof(message));

        if(code == 1){
            strcpy(message, "KM1");
        }else{
            strcpy(message, "KM1");
        }
        send(clients[0], message, sizeof(buffer), 0);

        close(clients[0]);
    }
    else{
        wait(NULL);
        printf("\n[!!!!!] Client B\n");
        // child process - B
        close(m[1]);
        read(m[0], &methods[1], sizeof(int));
        close(m[0]);
        if(send(clients[1], &methods[1], sizeof(int), 0) == 0){
            perror("[!!!] Fail to send confirmation to client B!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Method confirmation was sent to client B.\n");
        }

        memset(message, '\0', sizeof(message));
        message_length = encryptDataLibrary(key2, strlen(key2), key3, iv3, message);
        printf("\n[KM] Crypto text for keyB:\n");
        BIO_dump_fp(stdout, (const char*) message, message_length);

        if(send(clients[1], &message_length, sizeof(int), 0) == 0){
            perror("[!!!] Fail to send encrypted key length to client B!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted key length was sent to client B.\n");
        }


        if(send(clients[1], &message, strlen(message), 0) == 0){
            perror("[!!!] Fail to send encrypted key to client B!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted key was sent to client B.\n");
        }

        memset(message, '\0', sizeof(message));
        message_length = encryptDataLibrary(iv2, strlen(key2), key3, iv3, message);
        printf("\n[KM] Crypto text for ivB:\n");
        BIO_dump_fp(stdout, (const char*) message, message_length);

        if(send(clients[1], &message_length, sizeof(int), 0) == 0){
            perror("[!!!] Fail to send encrypted iv length to client B!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted iv length was sent to client B.\n");
        }

        if(send(clients[1], &message, strlen(message), 0) == 0){
            perror("[!!!] Fail to send encrypted iv to client B!\n");
            exit(EXIT_FAILURE);
        }else{
            printf("[info] Encrypted iv was sent to client B.\n");
        }

        char dataB[1024];
        int data_length = 0;
        memset(dataB, '\0', sizeof(dataB));

        close(p[1]);
        read(p[0], &data_length, sizeof(int));
        read(p[0], dataB, data_length);
        close(p[0]);

        printf("[info] Data length for client B: %d\n", data_length);
        printf("[info] Data for client B: %s\n", dataB);


        int encrypted_length;
        if(methods[1] == 0){
            encrypted_length = encryptDataCBC(dataB, key2, iv2);
        }else{
            encrypted_length = encryptDataCFB(dataB, key2, iv2);
        }

        int block_data_length = 32;
        printf("[info] Send number of blocks to B.\n");
        printf("[info] Number of blocks: %d.\n", no_blocks);
        send(clients[1], &no_blocks, sizeof(int),0);



        printf("[info] Send encrypted data to client B...\n");

        int block_hexdec_length = 32;
        char block_hex[33];
        memset(block_hex, '\0', sizeof(block_hex));
        for(int i=0;i<=encrypted_length;i++){
            if(i%32 == 0 && i != 0){
                send(clients[1], &block_hexdec_length, sizeof(int), 0);
                send(clients[1], &block_hex, block_hexdec_length, 0);
            }
            printf("%c ", crypt_data[i]);
            block_hex[i%32] = crypt_data[i];
        }

        printf("\n");

        printf("[info] Data was sent to client B.\n");
        int code;
        read(clients[1], &code, sizeof(int));
        
        close(r[0]);
        write(r[1], &code, sizeof(int));
        close(r[1]);


        close(clients[1]);
    }

    
    return;
}

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encryptDataLibrary(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){

    EVP_CIPHER_CTX *ctx;
    int length;
    int ciphertext_length;

    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1){
        handleErrors();
    }

    if(EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len) != 1){
        handleErrors();
    }

    ciphertext_length = length;

    if(EVP_EncryptFinal_ex(ctx, ciphertext+length, &length) != 1){
        handleErrors();
    }

    ciphertext_length += length;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_length;

}


int encryptDataCBC(unsigned char *plaintext, unsigned char *key, unsigned char *iv){
    
    printf("\n\n[***] CBC Encryption...\n\n");

    char plain_data[1024];

    memset(crypt_data, '\0', sizeof(crypt_data));
    memset(plain_data, '\0', sizeof(plain_data));

    strcpy(plain_data, plaintext);

    int padding = strlen(plain_data) % 16;
    int data_length = strlen(plain_data);

    printf("\n[info] Text length: %d\n", strlen(plain_data));
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
    printf("\n");
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
    printf("\n[BKEY] %s\n", key);
    printf("\n[BIV] %s\n", iv);
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
    no_blocks = block - 1;
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
    memset(crypt_data,'\0', sizeof(crypt_data));
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
    decrypt_dataB = crypt_data;
    return strlen(decrypt_dataB);
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
    memset(crypt_data, '\0', sizeof(crypt_data));

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

    decrypt_dataB = crypt_data;
    return strlen(decrypt_dataB);
}