# MQTT Scripting  

**Author: Sean Pesce**  

For complex use-cases that require multiple MQTT operations, AWS IoT Recon supports a simple script syntax for
automatically executing sequential MQTT actions.  

The scripting "language" supports four types of instructions (and comments):  

```
PUB	<topic>	<payload>
SUB	<topic>
UNSUB	<topic>
SLEEP	<milliseconds>
# Comment
```

Instruction arguments are separated/delimited by a tab character (`\t`), and empty/whitespace-only lines are ignored.  

`PUB` payloads can be provided in-line, but this will cause problems if the payload contains certain characters
(e.g., newline, tab, or non-printable byte values). For this reason, MQTT scripts have support for hex-encoding and
reading payloads from files:  

```
# Hex-encoded payload ("My vision is augmented")
PUB	<topic>	hex://4d7920766973696f6e206973206175676d656e746564

# Payload stored in the file /tmp/mqtt_payload.txt
PUB	<topic>	file:///tmp/mqtt_payload.txt
```

The following command demonstrates how to use the MQTT scripting feature of the recon tool:  

```
java -jar aws-iot-recon.jar -a mqtt-script -f $MQTT_SCRIPT_FILE -H $AWS_HOST -c $CLIENT_CERT -k $CLIENT_PRIVKEY
```

