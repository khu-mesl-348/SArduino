#include <sha256.h>
#include <SoftwareSerial.h>
#include <ISO7816.h>
#include <SecDevAPI.h>
#include <WiFi101.h>
#include <tropicssl.h>
#include <tropicssl/net.h>
#include <tropicssl/ssl.h>
#include <base64.h>

////////////// hex to base64 for certificate ////////////////
#define NELEMS(x) (sizeof(x) / sizeof(x[0]))

int check = 0;

///////// WiFi variable //////////
int status = WL_IDLE_STATUS;
WiFiClient client;

char ssid[] = "@348-MESL-2.4GHz";
char pass[] = "987654321f";    // your network password (use for WPA, or use as key for WEP)

#define SERVER_IP "192.168.1.121"
#define PORT 4000

////////// Socket data send/receive Variable ////////////////
String recvData;

//////// SSL /////////////
int ret, len, server_fd;
char buf[512] = "abc";
ssl_context ssl;

int sendMessage(char *buf, int sz) {
  int ret = 0;

  ret = client.write(buf, sz);
  return ret;
}

int recvMessage(char* buf, int sz) {
  int ret = 0;

  ret = client.read();
  return ret;
}

///// RSA Signature variable /////
byte signature[256] = {0};
int signlen = 0;
int sendsign = 0;

//////// Export RSA key variable /////////////
byte rsaValue[256] = {0};
int rsaValueLen = 0;
int sendMod = 0;

//////////// Device ID ///////////////
char deviceID[5] = "MESL1";
byte deviceID_hash[32];

int sendID = 0;

/////////// Application Hash ///////////////
byte app[32];

/////////// SE variable and function ////////////////

void dump(byte *buf, int len)
{
  int i;
  for (i = 0; i < len; ++i) {
    if (buf[i] < 16)
      Serial.print("0");

    Serial.print(buf[i], HEX);
    Serial.print(' ');

    if (i % 16 == 17)
      Serial.println();
    else if (i % 8 == 7)
      Serial.print(' ');
  }
  Serial.println();
}

void printRSAValue(char* title, byte* rsaValue, int rsaValueLen)
{
  Serial.print(title); Serial.print(": ");
  for (int i = 0; i < rsaValueLen; i++) {
    Serial.print(rsaValue[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

void probeOptigaP()
{
  //ApplicationHash(FW_Length());
  Serial.print("Hash the FW and the DeviceID... ");
  ApplicationHash(0x7530);
  getDeviceIDHash();
  Serial.println("[Success]");
  delay(2000);

  Serial.print("Generate a Signature... ");
  BYTE cmd_Gen_Signature[69] = {0x80, 0x8B, 0x00, 0x0E, 0x40};
  memcpy(cmd_Gen_Signature + 5, app, 32);
  memcpy(cmd_Gen_Signature + 37, deviceID_hash, 32);
  sendCommand("Gen_Signature", cmd_Gen_Signature, 69, signature, &signlen);
  Serial.println("[Success]");
  delay(2000);

  //  Serial.print("Signature: ");
  //  for (int i = 0; i < signlen; i++) {
  //    Serial.print(signature[i], HEX);
  //    Serial.print(" ");
  //  }
  //  Serial.println();
  ssl_write(&ssl, signature, signlen);
}

void sendCert()
{
  byte cert[48];
  int certlen = 0;
  char* stop = NULL;
  int test_b[48];

  Serial.print("Send a Signature and a Certificate... ");
  for (int i = 0; i < 12; i++) {
    BYTE cmd_LoadCert[5] = {0x80, 0x17, i + 9, 0x00, 0x30};
    sendCommand("LoadCert", cmd_LoadCert, 5, cert, &certlen);

    for (int j = 0; j < 48; j++)
      test_b[j] = (unsigned char)cert[j];

    int size_b = NELEMS(test_b);
    int out_size_b = b64e_size(size_b) + 1;
    unsigned char* out_b = malloc(out_size_b);

    out_size_b = b64_encode(test_b, size_b, out_b);
    ssl_write(&ssl, out_b, out_size_b);
    //    client.write(out_b, out_size_b);
    memset(cert, 0x00, 48);
    memset(test_b, 0x00, 48);
    delay(200);
  }
  ssl_write(&ssl, "end", 3);
  //  client.write("end");
  Serial.println("[Success]");
}

///////// Application Hash variable and function ///////////////
byte* digest = NULL;

void printHash(uint8_t* hash, int bytes_num) {
  for (int i = 0; i < bytes_num; i++) {
    Serial.print("0123456789abcdef"[hash[i] >> 4]);
    Serial.print("0123456789abcdef"[hash[i] & 0xf]);
  }
  Serial.println();
}

void ApplicationHash(unsigned long len) {
  Sha256_Hash(0x00000, len, app);
}

void getDeviceIDHash() {
  Sha256.init();
  for (int i = 0; i < 5; i++)
    Sha256.write(deviceID);

  byte* sendBuffer = Sha256.result();
  for (int i = 0; i < 32; i++)
    deviceID_hash[i] = sendBuffer[i];
  //  Serial.print("Device ID hash: ");
  //  printHash(deviceID_hash, 32);
  //  Serial.println();
}

void setup() {
  Serial.begin(9600, SERIAL_8E2);
  Serial3.begin(9600, SERIAL_8E2);
  
  ///// WIFI Connect /////
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    while (true);
  }

  while (status != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    status = WiFi.begin(ssid, pass);
    delay(1000);
  }

  ///// Connect Server /////
  Serial.print("\nRequest Connection to Server... ");
  if (server_fd = client.connect(SERVER_IP, PORT)) {
    Serial.println("[Success]");

    ssl_init(&ssl);
    ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
    ssl_set_bio(&ssl, recvMessage, &server_fd, sendMessage, &server_fd);
    ssl_set_ciphers(&ssl, ssl_default_ciphers);
    ssl_handshake(&ssl);
  }
}
void loop() {
  while (client.available()) {
    char c = (char)ssl_read(&ssl, buf, len);
    if (c == '\0') {
      if (recvData.equals("RequestAtt\n")) {
        sendsign = 1;
        recvData = "";
        // Serial.println("1");
      }
      else if (recvData.equals("RequestID\n")) {
        sendID = 1;
        recvData = "";
        //Serial.println("3");
      }
      else if (recvData.equals("VerifySuccess\n")) {
        //Serial.println();
        Serial.print("Receive a Comparison result... ");
        Serial.println("[Success]");
        delay(2000);
        Serial.println("Remote Attestation... [Success]");
        //        Serial.println("Execute App");
      }
      else if (recvData.equals("VerifyFail\n")) {
        //Serial.println();
        Serial.print("Receive a Comparison result... ");
        Serial.println("[Success]");
        delay(2000);
        Serial.println("Remote Attestation... [Error]");
        //Serial.println("4");
        while (1) {}
      }
    }
    else {
      recvData.concat(c);
      //      Serial.write(c);
    }
  }

  if (sendsign == 1) {
    if (Init_SE()) {
      probeOptigaP();
      sendCert();
      delay(100);
    }
    sendsign = 0;
  }

  if (sendID == 1) {
    ssl_write(&ssl, deviceID_hash, 32);
    delay(10);

    sendID = 0;
  }

  if (!client.connected()) {
    Serial.println();
    //Serial.println("disconnecting from server.");
    client.stop();

    while (true);
  }
}
