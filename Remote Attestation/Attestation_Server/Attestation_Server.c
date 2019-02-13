#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

void error_handling(char* message)
{
				fputs(message, stderr);
				fputc('\n', stderr);
				exit(1);
}

EVP_PKEY *extractPubkey()
{
				FILE* fp;
				EVP_PKEY *pkey = NULL;
				BIO *certbio = NULL;
				BIO *outbio = NULL;
				X509 *cert = NULL;
				int ret;

				certbio = BIO_new(BIO_s_file());
				outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

				ret = BIO_read_filename(certbio, "SECert");
				if(!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
								BIO_printf(outbio, "Error loading cert into memory\n");
								exit(-1);
				}

				if((pkey = X509_get_pubkey(cert)) == NULL)
								BIO_printf(outbio, "Error getting public key from certificate");

				X509_free(cert);
				BIO_free_all(certbio);
				BIO_free_all(outbio);

				return pkey;
}

int main(void)
{
				/////////// Socket Value for SSL Connection ///////
				int serv_sock, clnt_sock;
				struct sockaddr_in serv_addr, clnt_addr;
				int clnt_addr_size;
				int option = 1;

				////////// SSL value //////////////
				SSL_METHOD *method = NULL;
				SSL_CTX *ctx = NULL;
				SSL *ssl = NULL;

				/////////// Signature Decrypt Value /////////////
				RSA *pub_key = NULL;
				char modulus[1024] = "";
				char* pubExp = "010001";

				int sign_len = 0;
				char sign[1024];
				int d_sign_len;
				unsigned char d_sign[256];

				///////////// Application and Device ID hash ///////////////
				char *appData = NULL;
				char *deviceID = "MESL1";
				char appIDhash[65] = "";
				FILE *fp = NULL;
				int fileLen = 0;

				/// SHA-1 Value///
				SHA_CTX sha1;
				char sha1_str[SHA_DIGEST_LENGTH];

				/// SHA-256 Value ///
				SHA256_CTX sha256, sha256_2;
				char sha256_str[SHA256_DIGEST_LENGTH];

				///////////// Other Value //////////////////////
				int i = 0;
				char message[1024];
				char tempBuf[2];
				int socklen = 0;

				char cmpBuf[36] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
				int cmpchecknum = 0;

				/////////// Socket Connection Phase Start ////////////
				serv_sock = socket(PF_INET, SOCK_STREAM, 0);
				if(serv_sock == -1)
								error_handling("Socket() Error\n");
				setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

				memset(&serv_addr, 0, sizeof(serv_addr));
				serv_addr.sin_family = AF_INET;
				serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
				serv_addr.sin_port = htons(4000);

				if(bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
								error_handling("bind() Error\n");
				if(listen(serv_sock, 5) == -1)
								error_handling("listen() Error\n");

				clnt_addr_size = sizeof(clnt_addr);
				clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
				if(clnt_sock == -1)
								error_handling("accept() Error\n");
				else
								printf("Connection Success\n");

				/////////// Socket Connection Phase End ///////////////
				////////// SSL Connection Phase Start /////////////////
				SSL_load_error_strings();
				OpenSSL_add_ssl_algorithms();

				method = SSLv23_server_method();
				ctx = SSL_CTX_new(method);
				if(!ctx) {
								perror("Unable to create SSL context");
								ERR_print_errors_fp(stderr);
								exit(1);
				}

				ssl = SSL_new(ctx);
				SSL_Set_fd(ssl, clnt_sock);

				if(SSL_Accept(ssl) <= 0) {
								ERR_print_errors_fp(stderr);
				} else {
								printf("SSL Connection Success\n");
				}

				///////// SSL Connection Phase End /////////////////
				///////// Remote Attestation Phase Start //////////////////////
				printf("Request Attestation... \n\n");

				SSL_Write(ssl, "RequestAtt\n", sizeof("RequestAtt\n"));
				socklen = SSL_Read(ssl, sign, 1024);
				sign_len = socklen;

			
				//printf("sign_len: %d\n", sign_len);
				printf("Signature: ");
				for(i=0; i<sign_len; i++)
								printf("%02X ", (unsigned char)sign[i]);
				printf("\n\n");

				fp = fopen("SECert", "w");
				char begin[] = "-----BEGIN CERTIFICATE-----";
				char end[] = "-----END CERTIFICATE-----";
				char last[] = "hlpOdCT4AsKyy1i14agVedADzrYCqGgyOBWKkw==";

				fprintf(fp, "%s\n", begin);

				while(1)
				{
								socklen = SSL_Read(ssl, message, 1024);
								message[socklen] = 0;
								if(strcmp(message, "end")==0)
												break;
								else
								{
												fprintf(fp, "%s\n", message);
												printf("message: %s\n", message);
												memset(message, 0x00, 1024);
								}
				}

				fprintf(fp, "%s\n", last);
				fprintf(fp, "%s\n", end);
				fclose(fp);

				pub_key = EVP_PKEY_get1_RSA(extractPubkey());

				memset(d_sign, 0x00, sizeof(d_sign));

				sleep(7);
				d_sign_len = RSA_public_decrypt(sign_len, (unsigned char*)sign, d_sign, pub_key, RSA_PKCS1_PADDING);
				if(d_sign_len < 1) {
								printf("RSA Public Decrypt Error\n");
				}
				else {
								printf("Signature decryption Success\n\n");
								sleep(2);
								//for(i=0; i<d_sign_len; i++)
								//printf("DecryptData: %02X\n", d_sign[i]);
				}
				////////////// Signature Decrypt Phase End /////////////////////
				////////////// Signature Verify Phase Start ////////////////////
				fp = fopen("appData.bin", "rb");
				fseek(fp, 0L, SEEK_END);
				fileLen = ftell(fp);
				fseek(fp, 0L, SEEK_SET);
				appData = (char*)calloc(fileLen, sizeof(char));
				fread(appData, 1, fileLen, fp);
				fclose(fp);
				//printf("\n\nappData: %d\n\n", fileLen);
				fileLen = 30001;
				SHA256_Init(&sha256);
				SHA256_Update(&sha256, appData, fileLen);
				SHA256_Final(sha256_str, &sha256);

				printf("Firmware Hash value: ");
				for(i=0; i<SHA256_DIGEST_LENGTH; i++)
								printf("%02X ", (unsigned char)sha256_str[i]);

				printf("\n\n");
				for(i=0; i<SHA256_DIGEST_LENGTH; i++)
								appIDhash[i] = sha256_str[i];
				//strcat(appIDhash, sha256_str);
				memset(sha256_str, 0x00, sizeof(sha256_str));
				/*
					 SHA256_Init(&sha256);
					 SHA256_Update(&sha256, deviceID, strlen(deviceID));
					 SHA256_Final(sha256_str, &sha256);

					 for(i=0; i<SHA256_DIGEST_LENGTH; i++)
					 printf("SHA256: %02X\n", (unsigned char)sha256_str[i]);

					 strcat(appIDhash, sha256_str);
				 */

				sleep(3);
				memset(message, 0x00, sizeof(message));
				SSL_Write(ssl, "RequestID\n", sizeof("RequestID\n"));
				socklen = read(clnt_sock, message, 1024);

				printf("deviceIDhash_len: %d\n", socklen);
				printf("IDhash: ");
				for(i=0; i<socklen; i++)
								printf("%02X ", (unsigned char)message[i]);
				printf("\n\n");

				for(i=0; i<socklen; i++)
								appIDhash[SHA256_DIGEST_LENGTH+i] = message[i];
				//strcat(appIDhash, message);

				// printf("appIDhash_len: %d\n", strlen(appIDhash));
				//printf("appIDhash: ");
				//for(i=0; i<64; i++)
				//      printf("%02X ", (unsigned char)appIDhash[i]);
				// printf("\n\n");

				SHA1_Init(&sha1);
				SHA1_Update(&sha1, appIDhash, 64);
				SHA1_Final(sha1_str, &sha1);

				//	for(i=0; i<SHA_DIGEST_LENGTH; i++)
				//		printf("SHA1: %02X\n", (unsigned char)sha1_str[i]);

				for(i=0; i<SHA_DIGEST_LENGTH; i++)
								cmpBuf[15+i] = sha1_str[i];
				//strcat(cmpBuf, sha1_str);

				//      printf("cmpBuf: ");
				//    for(i=0; i<35; i++)
				//          printf("%02X ", (unsigned char)cmpBuf[i]);
				//  printf("\n\n");

				/*for(i=0; i<35; i++)
					{
					if((unsigned char)cmpBuf[i] !=  d_sign[i]) {
					printf("cmp %02X, dsign %02X\n", (unsigned char)cmpBuf[i], d_sign[i]);
					cmpchecknum = 1;
					printf("check i: %d\n", i);
					break;
					}
					}
				 */
				sleep(7);
				if(cmpchecknum == 0) {
								printf("Verify Success\n");
								sleep(2);
								SSL_Write(ssl, "VerifySuccess\n", sizeof("VerifySuccess\n"));
				}
				else {
								printf("Verify Fail\n");
								sleep(2);
								SSL_Write(ssl, "VerifyFail\n", sizeof("VerifyFail\n"));
				}
				///////////// Signature Verify Phase End //////////////////////
				///////////// Remote Attestation Phase End ////////////////////

				close(clnt_sock);	
				return 0;
}	
