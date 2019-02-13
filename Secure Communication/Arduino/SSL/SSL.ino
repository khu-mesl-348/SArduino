#include <SPI.h>
#include <WiFi101.h>
#include <tropicssl.h>
#include <tropicssl/net.h>
#include <tropicssl/ssl.h>

int status = WL_IDLE_STATUS;
WiFiClient client;

char ssid[] = "@348-MESL-2.4GHz"; //WIfi ID what you want to connect
char pass[] = "987654321f"; //Wifi Pasword

#define SERVER_IP "192.168.1.121" //Server IP Address
#define PORT 4000 // Port Number

int ret = 0;
ssl_context clientssl;
ssl_session sslclientsession;
int clientsocketfd;
char buf[] = "Client Hello World";

int ssl_send(unsigned char *buf, int len)
{
  int ret = 0;
  Serial.println("ssl_send start");
  ret = client.write(buf, len);
  
  return ret;
}

int ssl_recv(unsigned char *buf, int len)
{
  int ret = 0;
  Serial.println("ssl_recv start");
  ret = client.read(buf, len);
  
  return ret;
}

void setup() {
  Serial.begin(9600);

  //Start of WIFI Connect
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
  Serial.print("You're connected to the network");
  
  memset(&clientssl, 0, sizeof(ssl_context));
  memset(&sslclientsession, 0, sizeof(ssl_session));

  clientsocketfd = client.connect(SERVER_IP, PORT);
  if (clientsocketfd == 0)
    Serial.println("Connection failed");
  //End of WIFI Connect
  
  ret = ssl_init(&clientssl);
  if (ret != 0)
    Serial.println("ssl_init failed");

  ssl_set_endpoint(&clientssl, SSL_IS_CLIENT); //Set the current endpoint type(Server or Client)
  ssl_set_authmode(&clientssl, SSL_VERIFY_NONE); //Set the certificate verification mode0.0

  ssl_set_bio(&clientssl, ssl_recv, &clientsocketfd, ssl_send, &clientsocketfd); // Set the SSL read and write callbacks
  ssl_set_ciphers(&clientssl, ssl_default_ciphers); // Set the list of allowed ciphersutes(e.g., AES, RSA, etc...)
  ssl_set_session(&clientssl, 1, 600, &sslclientsession); //Set the session resuming flag, timeout and data
  
  if (ret = ssl_handshake(&clientssl)) //Perform the SSL handshake
  {
    Serial.print("handshake failed returned ");
    Serial.println(ret);
    return -1;
  }
  
  if ((ret = ssl_write(&clientssl, buf, strlen(buf) + 1)) <= 0)
  {
    Serial.print("ssl_write failed returned ");
    Serial.println(ret);
    return -1;
  }

  ssl_close_notify(&clientssl); //Notify the peer that the connection is being closed
  ssl_free(&clientssl); // Free an SSL context
}

void loop() {
  // put your main code here, to run repeatedly:

}
