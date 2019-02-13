void setup() {
  // put your setup code here, to run once:
  Serial2.begin(9600);
  Serial.begin(9600);
}

void loop() {
  if(Serial2.available()){
    char data = Serial2.read();
    Serial.print(data);
  }
  // put your main code here, to run repeatedly:

}
