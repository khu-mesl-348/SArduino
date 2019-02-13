#include <sha1.h>
#include <sha256.h>
#include <SecDevAPI.h>
#include <crc16.h>
#include <aes.h>
#include <string.h>
#include <uECC.h>

//Secure boot & firmware update variables
byte XOR_buffer[32];
byte pinCode[8];
byte app[32];
byte boot[32];

//Test variables
uint8_t test_PINCode[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
uint8_t test_New_PINCode[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
uint8_t test_hash[32]={0x01 ,0x02, 0x03, 0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x30,0x31,0x32};
uint8_t iv[]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t Device_ID[15] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15};
uint8_t out[64];
uint8_t AesBuffer[64] = {0};
uint8_t AesBuffer_update[80] = {0};

//Shared key variables
byte aesKey[16];

//Use for firmware update received data
byte data[47];

//Boot Flag variables
static byte bootFlag = BOOT_DEFAULT;
 
static int RNG(uint8_t *dest, unsigned size) { // Based on analogRead(0), generate ECC algorithm parameter for ECDH
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  return 1;
}

//Generate PIN code
void Gen_Pincode(int len) {
  Sha256_Hash(0x00000, len, app); //refer to SHA256 library
  Sha256_Hash(0x3E000, 0x3FD1C, boot); ////refer to SHA256 library

  for (int i = 0; i < 32; i++) {
    XOR_buffer[i] = app[i] ^ boot[i];
  }
  for (int i = 0; i < 8; i++) pinCode[i] = XOR_buffer[i];
}

void SecureBoot(){
  byte pinHash[64]={0};
  uint8_t prvMCU[29];
  uint8_t pubMCU[56];
  uint8_t secMCU[28];
  uint8_t pubSE[56];
  uint8_t tempBuffer[62];
  uint8_t nonce[2];
 
  const struct uECC_Curve_t * curve = uECC_secp224r1(); //define ECC algorithm, secp224r1
    
  Gen_Pincode(FW_Length()); //Generate PIN Code based on application service
 
  uECC_make_key(pubMCU, prvMCU, curve); //Generate public and private key of MCU

  if((SecDev_Req_Gen_ECC(tempBuffer, 62)) != 1) // Request public&private_SE to SE and receive public_SE
    Serial2.println("public key request is Failed...");

  memcpy(pubSE, tempBuffer + 6, 56);
  if((SecDev_Req_Gen_secKey(pubMCU, 56, nonce, 2)) != 1) //Transmit the public_MCU to SE and receive nonce value
    Serial2.println("Secret Key Generation Failed...");

  uECC_shared_secret(pubSE, prvMCU, secMCU, curve); //Generate secret_MCU by using public_SE
  
  Gen_Shared_Key(aesKey, secMCU, sizeof(secMCU)); // refer to SHA1 library

  //Make the verification data set(nonce, PIN Code, FW_hash, Device ID)
  pinHash[0] = nonce[0] & 0x0F;
  memcpy(pinHash + 1, test_PINCode, sizeof(test_PINCode));
  memcpy(pinHash + 9, test_hash, sizeof(test_hash));
  memcpy(pinHash + 41, Device_ID, sizeof(Device_ID));

  memset(AesBuffer, 0, sizeof(AesBuffer));
  AES128_CBC_encrypt_buffer(AesBuffer, pinHash, 64, aesKey, iv); //Encrypt verification data set

  int result = SecDev_Req_FW_Verify(AesBuffer, 64); //Transmit encrypted verification data set to SE for integrity check
  if(result == 0x01){
      Serial2.println("Success");
      Serial2.println("Application Service is running...");    
  }
  else if(result == 0x03) Serial2.println("PINCode Error");
  else if(result == 0x06) Serial2.println("Hash Error");
  else if(result == 0x07) Serial2.println("Device Id Error");
  else Serial2.println("Unknown Error");
  
  if(result != 0x01){
    bootFlag = BOOT_FAILURE;
    Serial2.println("Device Boot is failed...");
    FailLoop();
  }
}

void setup() {
  int i;
  Serial2.begin(9600);   //Monitor
  Serial3.begin(9600, SERIAL_8E2);  //MCU <-> SE
  Serial.begin(9600);  //MCU <-> Firwmare Server
  randomSeed(analogRead(0));
  uECC_set_rng(&RNG);
  Set_DeviceID(Device_ID);

  //application configuration
  //...

  if(!Init_SE()){  //connect to SE
    Serial2.println("SE Connection Failure");
  }
  SecureBoot(); //Execute Secure Boot
}

void loop() {
  //if secure boot is success, application service is executed
}

//Secure Firmware Update
void serialEvent() {
  while (Serial.available()) { 
    byte readlen = Serial.readBytes((byte*)data, 47); //receive the VP from Updater
    byte VP[80]={0}; 
    byte newFW_pinCode[8];
    byte nonce[2];
    char textString[16];

    unsigned short check = 0;
    check = verifyCRC16(data); // CRC check if VP is correct or not
    if(check!=(unsigned short)0){
      Serial.print(ERROR_CRC);
      return;
    }

    if(SecDev_Req_Nonce(nonce, 2) != 1) //request nonce value to SE
      Serial2.println("Request Nonce is Failed...");

    Gen_Pincode(FW_Length()); //Generate the current PIN Code

    //Add verification data set to VP
    VP[0] = nonce[0] & 0x0F; //Nonce[1]
    memcpy(VP + 1, data+1, 44); //Version[1], New Hash[32], Ownership PW[11]
    memcpy(VP + 45, test_PINCode, sizeof(test_PINCode)); //Current PIN Code[8]
//      for (int i = 0; i < 32; i++) {
//        XOR_buffer[i] = data[i + 5] ^ boot[i];
//      }
//      for (int i = 0; i < 8; i++) newFW_pinCode[i] = XOR_buffer[i];
    memcpy(VP + 53, test_New_PINCode, sizeof(test_New_PINCode)); //New PIN Code[8]
    memcpy(VP + 61, Device_ID, sizeof(Device_ID)); //Device ID[15]

    for(int i=0; i<80; i++){
      Serial2.print("VP[");
      Serial2.print(i);
      Serial2.print("] :");
      Serial2.println(VP[i], HEX);
    }
    AES128_CBC_encrypt_buffer(AesBuffer_update, VP, 80, aesKey, iv); //Encrpyt VP by using shared key

    int result =SecDev_Req_VP_Verify(AesBuffer_update, 80); //request VP check to SE
    switch(result){
      case 0x01: Serial.print(SUCCESS);
      case 0x02: Serial.print(ERROR_OWN);
      case 0x03: Serial.print(ERROR_CUR_PINCODE);
      case 0x04: Serial.print(ERROR_OLD_VER);
      case 0x07: Serial.print(ERROR_DEVICE);
      case 0x08: Serial.print(ERROR_NONCE);
      default:   Serial.print(UNKNOWN_ERROR);
    }
  }
}
