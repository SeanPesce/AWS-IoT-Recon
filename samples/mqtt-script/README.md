# MQTT Script Sample  

**Author: Sean Pesce**  

The sample MQTT script in this directory (`test.mqttsh`) can be used as a reference for MQTT script syntax, and for testing the underlying implementations in `MqttScript.java`.  

The following command can be used to test MQTT scripting functionality using this script:

```
java -jar aws-iot-recon.jar -a mqtt-script -H $AWS_ENDPOINT -f samples/mqtt-script/test.mqttsh -c $CLIENT_CERT -k $CLIENT_PRIVKEY
```

Note that the file payload test will cause a `FileNotFound` exception if this test is not executed from the project root directory.  
