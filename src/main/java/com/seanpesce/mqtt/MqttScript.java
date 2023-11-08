// Author: Sean Pesce
//
// MQTT scripts are a series of PUB/SUB/UNSUB/SLEEP instructions that are executed sequentially.
// SUB instructions will subscribe to the specified topic indefinitely and dump all
// received messages to standard output. UNSUB will unsubscribe from the specified topic.
// PUB instructions will publish the given payload to the specified topic. SLEEP
// instructions will sleep for the specified numer of milliseconds (interpreted as decimal).
// Instruction fields are tab-separated ("\t") by default. Empty lines or lines starting
// with a comment character (default: "#") are ignored. In-line and end-of-line comments
// are not supported. Unrecognized syntax will throw an error.
//
// SUB instruction syntax:
//   SUB	topic/to/use
//
// UNSUB instruction syntax:
//   UNSUB	topic/to/use
//
// PUB instruction format:
//   PUB	topic/to/use	payload
//
// SLEEP instruction syntax:
//   SLEEP	1000
//
// PUB Payloads can have three forms:
//   - Raw:  The data is used as it appears in the script file
//   - File: Payloads starting with "file://" will be treated as a file path. Payload
//           data will be read from the specified file.
//   - Hex:  Payloads starting with "hex://" will be treated as "hexlified" binary data.
//           The data will be "un-hexlified" to raw bytes before being used as the payload.

package com.seanpesce.mqtt;


import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.validation.constraints.NotNull;

import com.seanpesce.Util;


public class MqttScript {


    public static class Instruction {

        protected String op = null;
        protected String topic = null;
        protected byte[] payload = null;

        public static final String OP_PUBLISH     = "PUB";
        public static final String OP_SUBSCRIBE   = "SUB";
        public static final String OP_UNSUBSCRIBE = "UNSUB";
        public static final String OP_SLEEP       = "SLEEP";
        public static final List<String> SUPPORTED_OPERATIONS = Collections.unmodifiableList(Arrays.asList(new String[]{
            OP_PUBLISH,
            OP_SUBSCRIBE,
            OP_UNSUBSCRIBE,
            OP_SLEEP
        }));
        

        public Instruction(String op, String topic) {
            this(op, topic, null);
        }

        public Instruction(@NotNull String op, @NotNull String topic, byte[] payload) {
            String opUpper = op.toUpperCase();

            if (opUpper.equals(OP_SUBSCRIBE) || opUpper.equals(OP_UNSUBSCRIBE) || opUpper.equals(OP_SLEEP)) {
                if (payload != null && payload.length != 0) {
                    throw new UnsupportedOperationException(opUpper + " operation does not support payload data");
                }
                this.payload = null;

            } else if (opUpper.equals(OP_PUBLISH)) {
                this.payload = payload;
                if (this.payload == null) {
                    this.payload = new byte[0];
                }

            } else {
                throw new UnsupportedOperationException(op);
            }

            this.op = opUpper;

            if (opUpper.equals(OP_SLEEP)) {
                long sleepDelay = Long.parseLong(topic, 10);
                if (sleepDelay < 0) {
                    sleepDelay = 0;
                }
                this.topic = "" + sleepDelay;
            } else {
                this.topic = topic;
            }
        }


        public String getOp() {
            return this.op;
        }

        public String getTopic() {
            return this.topic;
        }

        public byte[] getPayload() {
            return this.payload;
        }

        public long getDelay() {
            if (this.getOp().equals(OP_SLEEP)) {
                return Long.parseLong(this.topic, 10);
            }
            throw new UnsupportedOperationException("Sleep delay unsupported for " + this.getOp());
        }

        public void setOp(@NotNull String op) {
            String opUpper = op.toUpperCase();
            if (SUPPORTED_OPERATIONS.contains(opUpper)) {
                this.op = opUpper;
            }
            throw new UnsupportedOperationException(op);
        }

        public void setTopic (@NotNull String topic) {
            if (this.getOp().equals(OP_SLEEP)) {
                long sleepDelay = Long.parseLong(topic, 10);
                if (sleepDelay < 0) {
                    sleepDelay = 0;
                }
                this.topic = "" + sleepDelay;
            } else {
                this.topic = topic;
            }
        }

        public void setDelay(long delay) {
            if (this.getOp().equals(OP_SLEEP)) {
                if (delay < 0) {
                    delay = 0;
                }
                this.topic = "" + delay;
            }
            throw new UnsupportedOperationException("Sleep delay unsupported for " + this.getOp());
        }

        public void setPayload(byte[] payload) {
            this.payload = payload;
        }

        public String toString() {
            String strVal = this.getOp() + FIELD_SEP + this.getTopic();
            // Stringify payload for PUB instruction
            if (this.getOp().equals(OP_PUBLISH)) {
                strVal += FIELD_SEP;

                ArrayList<Byte> payload = new ArrayList<Byte>();
                for (byte b : this.getPayload()) {
                    payload.add(b);
                }
                ArrayList<Byte> fieldSep = new ArrayList<Byte>();
                byte[] fieldSepBytes = FIELD_SEP.getBytes(CHARSET);
                for (byte b : fieldSepBytes) {
                    fieldSep.add(b);
                }
                // Check if newline or field separator are in the payload, and if so,
                // hexlify it. Otherwise, insert the raw payload.
                if (payload.contains(Byte.valueOf((byte)0x0a)) || Collections.indexOfSubList(payload, fieldSep) != -1) {
                    // Hexlify the payload
                    strVal += PAYLOAD_TYPE_HEX;
                    strVal += Util.bytesToHex(this.getPayload());
                } else {
                    // Insert the payload raw
                    strVal += new String(this.getPayload(), CHARSET);
                }
            }
            return strVal;
        }
    }
    

    // Special payload prefixes
    public static final String PAYLOAD_TYPE_FILE = "file://";
    public static final String PAYLOAD_TYPE_HEX  = "hex://";

    // Instruction field delimiter
    public static String FIELD_SEP = "\t";
    // Comment delimiter
    public static String COMMENT_DELIM = "#";

    public static Charset CHARSET = StandardCharsets.UTF_8;
    // Whether to remove leading/trailing whitespace from topic strings
    public static boolean TRIM_TOPICS = true;


    // Parse the specified file into a series of MQTT script instructions
    public static List<Instruction> parseFromFile(@NotNull String scriptFilePath) throws IOException {
        String scriptData = new String(Files.readAllBytes(Paths.get(scriptFilePath)), CHARSET);
        return parse(scriptData);
    }


    // Parse string data into a series of MQTT script instructions
    public static List<Instruction> parse(@NotNull String scriptData) throws IOException {
        ArrayList<Instruction> instructions = new ArrayList<Instruction>();
        String[] lines = scriptData.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String lineTrimmed = line.trim();

            // Ignore empty lines, lines that only contain whitespace, and comments
            if (lineTrimmed.isBlank() || lineTrimmed.startsWith(COMMENT_DELIM)) {
                continue;
            }

            String[] instructionFields = line.split(FIELD_SEP);
            if (instructionFields.length < 2 || instructionFields.length > 3) {
                throw new IOException("Invalid number of MQTT instruction fields (" + instructionFields.length + ") in line " + i+1);
            }

            // Clean up fields
            String op = instructionFields[0].trim();
            String topic = instructionFields[1];
            if (TRIM_TOPICS) {
                topic = topic.trim();
            }

            // Parse payload
            byte[] payload = null;
            if (instructionFields.length > 2) {
                payload = parsePayload(instructionFields[2]);
            }

            instructions.add(new Instruction(op, topic, payload));
        }

        return instructions;
    }


    // Determines whether a payload is raw data, a path to a file to read,
    // or a hex representation of bytes, and returns the parsed payload.
    public static byte[] parsePayload(String payload) throws IOException {
        if (payload == null) {
            return null;

        } else if (payload.startsWith(PAYLOAD_TYPE_FILE)) {
            String filePath = payload.substring(PAYLOAD_TYPE_FILE.length());
            return Files.readAllBytes(Paths.get(filePath));

        } else if (payload.startsWith(PAYLOAD_TYPE_HEX)) {
            String hexStr = payload.substring(PAYLOAD_TYPE_HEX.length());
            return Util.hexToBytes(hexStr.trim());
        }

        return payload.getBytes(CHARSET);
    }
}
