// Author: Sean Pesce
//
// References:
//   https://aws.github.io/aws-iot-device-sdk-java-v2/
//   https://docs.aws.amazon.com/iot/latest/developerguide
//   https://github.com/aws/aws-iot-device-sdk-java-v2/blob/main/samples/
//   https://explore.skillbuilder.aws/learn/course/external/view/elearning/5667/deep-dive-into-aws-iot-authentication-and-authorization
//
// @TODO:
//   - Re-architect this tool to be more object-oriented (e.g., fewer static/global variables)
//   - Use CountDownLatch(count) in subscription message handlers for improved reliability

package com.seanpesce.aws.iot;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.security.cert.CertificateException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

import com.seanpesce.aws.iot.AwsIotConstants;
import com.seanpesce.http.MtlsHttpClient;
import com.seanpesce.mqtt.MqttScript;
import com.seanpesce.regex.PatternWithNamedGroups;
import com.seanpesce.Util;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import software.amazon.awssdk.crt.auth.credentials.Credentials;
import software.amazon.awssdk.crt.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.crt.auth.credentials.X509CredentialsProvider;
import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.io.ClientTlsContext;
import software.amazon.awssdk.crt.io.TlsContextOptions;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents;
import software.amazon.awssdk.crt.mqtt.MqttMessage;
import software.amazon.awssdk.crt.mqtt.QualityOfService;
import software.amazon.awssdk.crt.mqtt5.Mqtt5Client;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;
import software.amazon.awssdk.regions.Region;
// import software.amazon.awssdk.services.iotdataplane.IotDataPlaneClient;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;


public class AwsIotRecon {

    // MQTT topics to subscribe to (if empty, defaults to "#" - all topics)
    public static ArrayList<String> topicSubcriptions = new ArrayList<String>();

    // Regular expressions with named capture groups for harvesting fields from MQTT topics
    public static ArrayList<PatternWithNamedGroups> topicsRegex = new ArrayList<PatternWithNamedGroups>(Arrays.asList(AwsIotConstants.RESERVED_TOPICS_REGEX));

    public static String jarName = AwsIotRecon.class.getSimpleName() + ".jar";
    
    // Run-time resources
    public static CommandLine cmd = null;
    public static String clientId = null;
    public static MqttClientConnection clientConnection = null;
    public static Mqtt5Client mqtt5ClientConnection = null;
    public static ClientTlsContext tlsContext = null;  // For assuming IAM roles

    
    public static final MqttClientConnectionEvents connectionCallbacks = new MqttClientConnectionEvents() {
        @Override  // software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents
        public void onConnectionInterrupted(int errorCode) {
            System.err.println("[WARNING] Connection interrupted: (" + errorCode + ") " + CRT.awsErrorName(errorCode) + ": " + CRT.awsErrorString(errorCode));
        }

        @Override  // software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents
        public void onConnectionResumed(boolean sessionPresent) {
            System.err.println("[INFO] Connection resumed (" + (sessionPresent ? "existing" : "new") + " session)");
        }
    };


    public static final Consumer<MqttMessage> genericMqttMsgConsumer = new Consumer<MqttMessage>() {
        @Override
        public void accept(MqttMessage message) {
            String msg = "\n[MQTT Message] " + message.getTopic() + "\t" + new String(message.getPayload(), StandardCharsets.UTF_8);
            System.out.println(msg);
        }
    };


    public static final Consumer<MqttMessage> topicFieldHarvester = new Consumer<MqttMessage>() {
        @Override
        public void accept(MqttMessage message) {
            Map<String, String> m = extractFieldsFromTopic(message.getTopic());
            if (m != null) {
                String msg = "[MQTT Topic Field Harvester] " + message.getTopic() + "\t" + m;
                System.out.println(msg);
            }
        }
    };
    


    public static void main(String[] args) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, org.apache.commons.cli.ParseException, InterruptedException, ExecutionException {

        cmd = parseCommandLineArguments(args);
        buildConnection(cmd);

        String action = cmd.getOptionValue("a");
        if (action.equals(AwsIotConstants.ACTION_MQTT_DUMP)) {
            mqttConnect();
            beginMqttDump();

        } else if (action.equals(AwsIotConstants.ACTION_MQTT_TOPIC_FIELD_HARVEST)) {
            mqttConnect();
            beginMqttTopicFieldHarvesting();

        } else if (action.equals(AwsIotConstants.ACTION_IAM_CREDS)) {
            getIamCredentialsFromDeviceX509(cmd.hasOption("R") ? Util.getTextFileDataFromOptionalPath(cmd.getOptionValue("R")).split("\n") : new String[] {"admin"}, cmd.hasOption("t") ? cmd.getOptionValue("t") : clientId);

        } else if (action.equals(AwsIotConstants.ACTION_MQTT_SCRIPT)) {
            mqttConnect();
            runMqttScript(cmd.getOptionValue("f"));

        } else if (action.equals(AwsIotConstants.ACTION_MQTT_DATA_EXFIL)) {
            mqttConnect();
            testDataExfilChannel();
        
        } else if (action.equals(AwsIotConstants.ACTION_GET_JOBS)) {
            mqttConnect();
            getPendingJobs();

        } else if (action.equals(AwsIotConstants.ACTION_GET_SHADOW)) {
            getDeviceShadow(cmd.hasOption("t") ? cmd.getOptionValue("t") : clientId, cmd.hasOption("s") ? cmd.getOptionValue("s") : null);

        } else if (action.equals(AwsIotConstants.ACTION_LIST_NAMED_SHADOWS)) {
            getNamedShadows(cmd.hasOption("t") ? cmd.getOptionValue("t") : clientId);

        } else if (action.equals(AwsIotConstants.ACTION_LIST_RETAINED_MQTT_MESSAGES)) {
            getRetainedMqttMessages();
        }

        // System.exit(0);
    }


    public static CommandLine parseCommandLineArguments(String[] args) throws IOException {
        // Get JAR name for help output
        try {
            jarName = AwsIotRecon.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            jarName = jarName.substring(jarName.lastIndexOf(FileSystems.getDefault().getSeparator()) + 1);
        } catch (URISyntaxException ex) {
            // Do nothing
        }

        // Parse command-line arguments
        Options opts = new Options();
        Option optHelp = new Option("h", "help", false, "Print usage and exit");
        opts.addOption(optHelp);
        Option optAwsHost = Option.builder("H").longOpt("host").argName("host").hasArg(true).required(true).desc("(Required) AWS IoT instance hostname").type(String.class).build();
        opts.addOption(optAwsHost);
        Option optOperation = Option.builder("a").longOpt("action").argName("action").hasArg(true).required(true).desc("(Required) The enumeration task to carry out. Options: " + AwsIotConstants.CLI_ACTIONS).type(String.class).build();
        opts.addOption(optOperation);
        Option optMqttUser = Option.builder("u").longOpt("user").argName("username").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Username for connection").type(String.class).build();
        opts.addOption(optMqttUser);
        Option optMqttPw = Option.builder("p").longOpt("pass").argName("password").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Password for connection").type(String.class).build();
        opts.addOption(optMqttPw);
        Option optMtlsCert = Option.builder("c").longOpt("mtls-cert").argName("cert").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Client mTLS certificate (file path or string data)").type(String.class).build();
        opts.addOption(optMtlsCert);
        Option optMtlsPrivKey = Option.builder("k").longOpt("mtls-priv-key").argName("key").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Client mTLS private key (file path or string data)").type(String.class).build();
        opts.addOption(optMtlsPrivKey);
        Option optMtlsKeystore = Option.builder("K").longOpt("mtls-keystore").argName("keystore").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Path to keystore file (PKCS12/P12 or Java Keystore/JKS) containing client mTLS key pair. If keystore alias and/or certificate password is specified, the keystore is assumed to be a JKS file. Otherwise, the keystore is assumed to be P12").type(String.class).build();
        opts.addOption(optMtlsKeystore);
        Option optMtlsKeystorePw = Option.builder("q").longOpt("keystore-pass").argName("password").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Password for mTLS keystore (JKS or P12). Required if a keystore is specified").type(String.class).build();
        opts.addOption(optMtlsKeystorePw);
        Option optMtlsKeystoreAlias = Option.builder("N").longOpt("keystore-alias").argName("alias").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Alias for mTLS keystore (JKS)").type(String.class).build();
        opts.addOption(optMtlsKeystoreAlias);
        Option optMtlsKeystoreCertPw = Option.builder("Q").longOpt("keystore-cert-pass").argName("password").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Certificate password for mTLS keystore (JKS)").type(String.class).build();
        opts.addOption(optMtlsKeystoreCertPw);
        Option optMtlsWindowsCertPath = Option.builder(null).longOpt("windows-cert-store").argName("path").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Path to mTLS certificate in a Windows certificate store").type(String.class).build();
        opts.addOption(optMtlsWindowsCertPath);
        Option optCertificateAuthority = Option.builder("A").longOpt("cert-authority").argName("cert").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Certificate authority (CA) to use for verifying the server TLS certificate (file path or string data)").type(String.class).build();
        opts.addOption(optCertificateAuthority);
        Option optUseMqtt5 = new Option("5", "mqtt5", false, "Use MQTT 5");
        opts.addOption(optUseMqtt5);
        Option optClientId = Option.builder("C").longOpt("client-id").argName("ID").hasArg(true).required(false).desc("Client ID to use for connections. If no client ID is provided, a unique ID will be generated every time this program runs.").type(String.class).build();
        opts.addOption(optClientId);
        Option optPortNum = Option.builder("P").longOpt("port").argName("port").hasArg(true).required(false).desc("AWS server port number (1-65535)").type(Number.class).build();
        opts.addOption(optPortNum);
        Option optTopicRegex = Option.builder("X").longOpt("topic-regex").argName("regex").hasArg(true).required(false).desc("Regular expression(s) with named capture groups for harvesting metadata from MQTT topics. This argument can be a file path or regex string data. To provide multiple regexes, separate each expression with a newline character. For more information on Java regular expressions with named capture groups, see here: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/regex/Pattern.html#special").type(String.class).build();
        opts.addOption(optTopicRegex);
        Option optNoVerifyTls = new Option("U", "unsafe-tls", false, "Disable TLS certificate validation when possible");  // @TODO: Disable TLS validation for MQTT too?
        opts.addOption(optNoVerifyTls);
        Option optRoleAlias = Option.builder("R").longOpt("role-alias").argName("role").hasArg(true).required(false).desc("IAM role alias to obtain credentials for. Accepts a single alias string, or a path to a file containing a list of aliases.").type(String.class).build();
        opts.addOption(optRoleAlias);
        Option optSubToTopics = Option.builder("T").longOpt("topics").argName("topics").hasArg(true).required(false).desc("MQTT topics to subscribe to (file path or string data). To provide multiple topics, separate each topic with a newline character").type(String.class).build();
        opts.addOption(optSubToTopics);
        Option optThingName = Option.builder("t").longOpt("thing-name").argName("name").hasArg(true).required(false).desc("Unique \"thingName\" (device ID). If this argument is not provided, client ID will be used").type(String.class).build();
        opts.addOption(optThingName);
        Option optShadowName = Option.builder("s").longOpt("shadow-name").argName("name").hasArg(true).required(false).desc("Shadow name (required for fetching named shadows with " + AwsIotConstants.ACTION_GET_SHADOW + ")").type(String.class).build();
        opts.addOption(optShadowName);
        Option optCustomAuthUser = Option.builder(null).longOpt("custom-auth-user").argName("user").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Custom authorizer username").type(String.class).build();
        opts.addOption(optCustomAuthUser);
        Option optCustomAuthName = Option.builder(null).longOpt("custom-auth-name").argName("name").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Custom authorizer name").type(String.class).build();
        opts.addOption(optCustomAuthName);
        Option optCustomAuthSig = Option.builder(null).longOpt("custom-auth-sig").argName("signature").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Custom authorizer signature").type(String.class).build();
        opts.addOption(optCustomAuthSig);
        Option optCustomAuthPass = Option.builder(null).longOpt("custom-auth-pass").argName("password").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Custom authorizer password").type(String.class).build();
        opts.addOption(optCustomAuthPass);
        Option optCustomAuthTokKey = Option.builder(null).longOpt("custom-auth-tok-name").argName("name").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Custom authorizer token key name").type(String.class).build();
        opts.addOption(optCustomAuthTokKey);
        Option optCustomAuthTokVal = Option.builder(null).longOpt("custom-auth-tok-val").argName("value").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "Custom authorizer token value").type(String.class).build();
        opts.addOption(optCustomAuthTokVal);
        Option optMqttScript = Option.builder("f").longOpt("script").argName("file").hasArg(true).required(false).desc("MQTT script file (required for " + AwsIotConstants.ACTION_MQTT_SCRIPT + " action)").type(String.class).build();
        opts.addOption(optMqttScript);
        Option optAwsRegion = Option.builder("r").longOpt("region").argName("region").hasArg(true).required(false).desc("AWS instance region (e.g., \"us-west-2\") - only required when using MQTT-over-WebSocket").type(String.class).build();
        opts.addOption(optAwsRegion);

        // https://gist.github.com/SeanPesce/017773ff5cb919364de3f55f6ff086e2
        Option optAwsAccessKeyId = Option.builder(null).longOpt("aws-access-key-id").argName("id").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS AccessKeyId (for WebSocket auth)").type(String.class).build();
        opts.addOption(optAwsAccessKeyId);
        Option optAwsSecretKey = Option.builder(null).longOpt("aws-secret-key").argName("id").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS secret key (for WebSocket auth)").type(String.class).build();
        opts.addOption(optAwsSecretKey);
        Option optAwsSessionToken = Option.builder(null).longOpt("aws-session-token").argName("token").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS session token (for WebSocket auth)").type(String.class).build();
        opts.addOption(optAwsSessionToken);

        // @TODO: Implement Cognito authentication flows
        // AWS Cognito options
        // https://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/cognitoidp/model/AuthFlowType.html
        // Option optCognitoAuthFlow = Option.builder(null).longOpt("cognito-auth-flow").argName("flow-type").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS Cognito auth flow type (for Signature v4 auth)").type(String.class).build();
        // opts.addOption(optCognitoAuthFlow);
        // Option optCognitoClientId = Option.builder(null).longOpt("cognito-client-id").argName("id").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS Cognito client ID (for Signature v4 auth)").type(String.class).build();
        // opts.addOption(optCognitoClientId);
        // Option optCognitoUserPoolId = Option.builder(null).longOpt("cognito-user-pool-id").argName("id").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS Cognito user pool ID (for Signature v4 auth)").type(String.class).build();
        // opts.addOption(optCognitoUserPoolId);
        // Option optCognitoIdentityPoolId = Option.builder(null).longOpt("cognito-identity-pool-id").argName("id").hasArg(true).required(false).desc(AwsIotConstants.CLI_AUTH_ARG + "AWS Cognito identity pool ID (for Signature v4 auth)").type(String.class).build();
        // opts.addOption(optCognitoIdentityPoolId);

        // @TODO: Add support for these:
        //        Connection options:
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withCustomAuthorizer(java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String,java.lang.String)
        //            See also: https://github.com/aws/aws-iot-device-sdk-java-v2/blob/main/samples/CustomAuthorizerConnect/src/main/java/customauthorizerconnect/CustomAuthorizerConnect.java#L70
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withHttpProxyOptions(software.amazon.awssdk.crt.http.HttpProxyOptions)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqtt5ClientBuilder.html
        //
        //        Timeout options:
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withKeepAliveSecs(int)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withPingTimeoutMs(int)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withProtocolOperationTimeoutMs(int)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withReconnectTimeoutSecs(long,long)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withTimeoutMs(int)
               
        // Websocket options:
        Option optUseWebsocket = new Option("w", "websocket", false, "Use Websockets");
        opts.addOption(optUseWebsocket);
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withWebsocketCredentialsProvider(software.amazon.awssdk.crt.auth.credentials.CredentialsProvider)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withWebsocketSigningRegion(java.lang.String)
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withWebsocketProxyOptions(software.amazon.awssdk.crt.http.HttpProxyOptions)
        //
        //        Other miscellaneous options:
        //        https://aws.github.io/aws-iot-device-sdk-java-v2/software/amazon/awssdk/iot/AwsIotMqttConnectionBuilder.html#withWill(software.amazon.awssdk.crt.mqtt.MqttMessage)

        CommandLine cmd = null;
        CommandLineParser cmdParser = new BasicParser();
        final String usagePrefix = "java -jar " + jarName + " -H <host> -a <action> [options]";//+ "\n\n" + AwsIotConstants.PROJECT_TITLE + "\n\n";
        HelpFormatter helpFmt = new HelpFormatter();

        // Determine the width of the terminal environment
        String columnsEnv = System.getenv("COLUMNS");  // Not exported by default.  @TODO: Do something better to determine console width?
        int terminalWidth = 120;
        if (columnsEnv != null) {
            try {
                terminalWidth = Integer.parseInt(columnsEnv);
            } catch (NumberFormatException ex) {
                // Do nothing here; use default width
            }
        }
        helpFmt.setWidth(terminalWidth);

        // Check if "help" argument was passed in
        if (Arrays.stream(args).anyMatch(arg -> arg.equals("--help") || arg.equals("-h"))) {
            helpFmt.printHelp(usagePrefix, "\n", opts, "\n\n"+AwsIotConstants.PROJECT_TITLE);
            System.exit(0);
        }

        try {
            cmd = cmdParser.parse(opts, args);

            // Check for valid action
            String action = cmd.getOptionValue("a");
            if (!AwsIotConstants.CLI_ACTIONS.contains(action)) {
                throw new org.apache.commons.cli.ParseException("Invalid action: \"" + action + "\"");
            }
        } catch (org.apache.commons.cli.ParseException ex) {
            System.err.println("[ERROR] " + ex.getMessage() + "\n");
            helpFmt.printHelp(usagePrefix, "\n", opts, "\n\n"+AwsIotConstants.PROJECT_TITLE);
            System.exit(154);
        }

        // Add any manually-specified topic subscriptions
        if (cmd.hasOption("T")) {
            String topicStr = Util.getTextFileDataFromOptionalPath(cmd.getOptionValue("T"));
            String[] topicStrs = topicStr.split("\n");
            for (String t : topicStrs) {
                System.err.println("[INFO] Adding custom MQTT topic subscription: " + t);
                topicSubcriptions.add(t);
            }
            System.err.println("[INFO] Added " + topicStrs.length + " custom MQTT topic subscription" + (topicStrs.length == 1 ? "" : "s"));
        }

        // Add any manually-specified topic regexes
        if (cmd.hasOption("X")) {
            String topicRegexStr = Util.getTextFileDataFromOptionalPath(cmd.getOptionValue("X"));
            String[] topicRegexStrs = topicRegexStr.split("\n");
            for (String r : topicRegexStrs) {
                System.err.println("[INFO] Adding custom MQTT topic regex: " + r);
                topicsRegex.add(PatternWithNamedGroups.compile(r));
            }
            System.err.println("[INFO] Added " + topicRegexStrs.length + " custom MQTT topic regular expression" + (topicRegexStrs.length == 1 ? "" : "s"));
        }

        return cmd;
    }



    public static void buildConnection(CommandLine cmd) throws CertificateException, FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, org.apache.commons.cli.ParseException {
        // Determine how to initialize the connection builder
        AwsIotMqttConnectionBuilder connBuilder = null;
        TlsContextOptions tlsCtxOpts = null;

        String action = cmd.getOptionValue("a");

        // Check for arguments required for specific actions
        if (action.equals(AwsIotConstants.ACTION_MQTT_DUMP)) {
            // Nothing required except auth data

        } else if (action.equals(AwsIotConstants.ACTION_MQTT_TOPIC_FIELD_HARVEST)) {
            // Nothing required except auth data

        } else if (action.equals(AwsIotConstants.ACTION_IAM_CREDS)) {
            if (!cmd.hasOption("R")) {
                throw new IllegalArgumentException("Operation " + action + " requires role(s) to be specified with \"-R\"");
            }

        } else if (action.equals(AwsIotConstants.ACTION_MQTT_SCRIPT)) {
            if (!cmd.hasOption("f")) {
                System.err.println("[ERROR] \"" + action + "\" action requires an MQTT script file (\"-f\")");
                System.exit(3);
            }

        } else if (action.equals(AwsIotConstants.ACTION_MQTT_DATA_EXFIL)) {
            // Nothing required except auth data
        
        } else if (action.equals(AwsIotConstants.ACTION_GET_JOBS)) {
            if (!(cmd.hasOption("t") || cmd.hasOption("C"))) {
                System.err.println("[ERROR] \"" + action + "\" action requires thing name (\"-t\") or client ID (\"-C\")");
                System.exit(3);
            }

        } else if (action.equals(AwsIotConstants.ACTION_GET_SHADOW)) {
            // @TODO: Improve implementation to support this action in more ways
            if (!(cmd.hasOption("c") && cmd.hasOption("k") && cmd.hasOption("A"))) {
                System.err.println("[ERROR] \"" + action + "\" action currently requires file paths for client certificate (\"-c\"), client private key (\"-k\"), and certificate authority (\"-A\")");
                System.exit(3);
            }
            if (!(cmd.hasOption("t") || cmd.hasOption("C"))) {
                System.err.println("[ERROR] \"" + action + "\" action requires thing name (\"-t\") or client ID (\"-C\")");
                System.exit(3);
            }

        } else if (action.equals(AwsIotConstants.ACTION_LIST_NAMED_SHADOWS)) {
            // @TODO: Improve implementation to support this action in more ways
            if (!(cmd.hasOption("c") && cmd.hasOption("k") && cmd.hasOption("A"))) {
                System.err.println("[ERROR] \"" + action + "\" action currently requires file paths for client certificate (\"-c\"), client private key (\"-k\"), and certificate authority (\"-A\")");
                System.exit(3);
            }
            if (!(cmd.hasOption("t") || cmd.hasOption("C"))) {
                System.err.println("[ERROR] \"" + action + "\" action requires thing name (\"-t\") or client ID (\"-C\")");
                System.exit(3);
            }


        } else if (action.equals(AwsIotConstants.ACTION_LIST_RETAINED_MQTT_MESSAGES)) {
            // @TODO: Improve implementation to support this action in more ways
            if (!(cmd.hasOption("c") && cmd.hasOption("k") && cmd.hasOption("A"))) {
                System.err.println("[ERROR] \"" + action + "\" action currently requires file paths for client certificate (\"-c\"), client private key (\"-k\"), and certificate authority (\"-A\")");
                System.exit(3);
            }

        }

        // Determine authentication mechanism
        boolean customAuth = false;
        boolean sigV4Auth  = false;
        
        if (cmd.hasOption("c") && cmd.hasOption("k")) {
            // mTLS using specified client certificate and private key
            String cert = Util.getTextFileDataFromOptionalPath(cmd.getOptionValue("c"));
            String privKey = Util.getTextFileDataFromOptionalPath(cmd.getOptionValue("k"));
            connBuilder = AwsIotMqttConnectionBuilder.newMtlsBuilder(cert, privKey);
            tlsCtxOpts = TlsContextOptions.createWithMtls(cert, privKey);

        } else if (cmd.hasOption("K")) {
            // mTLS using keystore file
            String ksPath = cmd.getOptionValue("K");
            if (!cmd.hasOption("q")) {
                System.err.println("[ERROR] Provide a keystore password with \"-q\"");
                System.exit(1);
            }
            String ksPw = cmd.getOptionValue("q");
            if (cmd.hasOption("N") || cmd.hasOption("Q")) {
                // JKS keystore
                if (!cmd.hasOption("N")) {
                    System.err.println("[ERROR] JKS keystore requires a keystore alias. Provide an alias with \"-A\"");
                    System.exit(1);
                } else if (!cmd.hasOption("Q")) {
                    System.err.println("[ERROR] JKS keystore requires a certificate password. Provide a password with \"-Q\"");
                    System.exit(1);
                }
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream(ksPath), ksPw.toCharArray());
                String ksAlias = cmd.getOptionValue("N");
                String certPw = cmd.getOptionValue("Q");
                connBuilder = AwsIotMqttConnectionBuilder.newJavaKeystoreBuilder(ks, ksAlias, certPw);
                tlsCtxOpts = TlsContextOptions.createWithMtlsJavaKeystore​(ks, ksAlias, certPw);
            } else {
                // P12 keystore
                connBuilder = AwsIotMqttConnectionBuilder.newMtlsPkcs12Builder(ksPath, ksPw);
                tlsCtxOpts = TlsContextOptions.createWithMtlsPkcs12​(ksPath, ksPw);
            }

        } else if (cmd.hasOption("windows-cert-store")) {
            // mTLS using Windows certificate store
            String winStorePath = cmd.getOptionValue("W");
            connBuilder = AwsIotMqttConnectionBuilder.newMtlsWindowsCertStorePathBuilder(winStorePath);
            tlsCtxOpts = TlsContextOptions.createWithMtlsWindowsCertStorePath​(winStorePath);
        
        } else if (cmd.hasOption("custom-auth-name") || cmd.hasOption("custom-auth-sig")
                    || cmd.hasOption("custom-auth-tok-name") || cmd.hasOption("custom-auth-tok-val")
                    || cmd.hasOption("custom-auth-user") || cmd.hasOption("custom-auth-pass")) {
            // Custom authentication
            customAuth = true;
            connBuilder = AwsIotMqttConnectionBuilder.newDefaultBuilder();
            connBuilder = connBuilder.withCustomAuthorizer(
                cmd.getOptionValue("custom-auth-user"),
                cmd.getOptionValue("custom-auth-name"),
                cmd.getOptionValue("custom-auth-sig"),  // @TODO: "It is strongly suggested to URL-encode this value; the SDK will not do so for you."
                cmd.getOptionValue("custom-auth-pass"),
                cmd.getOptionValue("custom-auth-tok-name"),  // @TODO: "It is strongly suggested to URL-encode this value; the SDK will not do so for you."
                cmd.getOptionValue("custom-auth-tok-val")
            );
            tlsCtxOpts = TlsContextOptions.createDefaultClient();

        } else if (cmd.hasOption("w")) {
            connBuilder = AwsIotMqttConnectionBuilder.newDefaultBuilder();
            connBuilder = connBuilder.withWebsockets(true);

            if (!cmd.hasOption("r")) {
                System.err.println("[ERROR] MQTT over WebSocket requires region (\"-r\")");
                System.exit(1);
            }
            // @TODO: Implement Cognito authentication flows
            // if (cmd.hasOption("u") && cmd.hasOption("p")
            //      && cmd.hasOption("cognito-auth-flow") && cmd.hasOption("cognito-client-id")
            //      && cmd.hasOption("cognito-identity-pool-id") && cmd.hasOption("cognito-user-pool-id")) {
            //     sigV4Auth = true;
            //     Region region = Region.of(cmd.getOptionValue("r"));
            //     String userPoolId = cmd.getOptionValue("cognito-user-pool-id");
            //     CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder().region(region).build();
            //     AuthFlowType authFlow = AuthFlowType.valueOf(cmd.getOptionValue("cognito-auth-flow"));
            //     Map<String, String> authParams = new HashMap<>();
            //
            //     // authParams.put("DEVICE_KEY", "abcdevicekey");  // @TODO: Do we even need this field? (I don't think so)
            //
            //     switch (authFlow) {
            //         case USER_SRP_AUTH:
            //             authParams.put("USERNAME", cmd.getOptionValue("u"));
            //             // authParams.put("SECRET_HASH", cmd.getOptionValue("p"));  // @TODO
            //             // @TODO: Add and use this class to generate a secure SRP_A value:
            //             // https://github.com/aws/aws-sdk-java/issues/1403#issuecomment-352073758
            //             authParams.put("SRP_A", "553CD35F53991F47A7E868542861E2FB02A5DAA4FB01D038668D0B68823B4445CACBCD8671A596F1E2CE2ED6CD8DA72909876930B225FE1D84E7D441CCFE99987DAC13ADD0D2EB36E6840E31916C186F8C36C2FDA559BACE8CE9AAC8284AF3EC82CBC951B4156AD8CCF608BA805EF86D0164D58699D646607A760193A62F548EB77D0935C65555B33B488BE7F35756ACD4206767E4F356924AC98113BC4639754D6C3778C68B4E7FC86F2D4F4942FB0731557B19AF13286B1269C1B7E08331BAEC071E1FFA1E928C45406DCE74A0CBD0061220955C2CB36DE20F885AC4394E523A19EA34568D54FC4BFC6E1631F3C9631268AF7221C9E1BD7DBC095298A930A1F6ACDC4A6A4B22484400AF6603DD70DEB746F38BD00640962D42A52345D787E1E3BB4A07D9D7E5BAA9C0681D2A661851909FA4B9702164CD0DE1F5EFCA4A6FACF902F9C26214BF1416299FAAF8A2A83A1DCF57B31230FEA9CA8663AF7FA8FB2A4E7B0A963BD380DEB2753E1B2E18785185EB84B01AACDC9EA777FFFFC176A2F2");
            //             break;
            //         case USER_PASSWORD_AUTH:
            //             authParams.put("USERNAME", cmd.getOptionValue("u"));
            //             authParams.put("PASSWORD", cmd.getOptionValue("p"));
            //             break;
            //         case REFRESH_TOKEN_AUTH:
            //         case REFRESH_TOKEN:
            //             authParams.put("REFRESH_TOKEN", cmd.getOptionValue("u"));
            //             // authParams.put("SECRET_HASH", cmd.getOptionValue("p"));  // @TODO
            //             break;
            //         case CUSTOM_AUTH:
            //             authParams.put("USERNAME", cmd.getOptionValue("u"));
            //             // authParams.put("SECRET_HASH", cmd.getOptionValue("p"));  // @TODO
            //             break;
            //         default:
            //             System.err.println("[ERROR] Unsupported auth flow type: " + cmd.getOptionValue("cognito-auth-flow"));
            //             System.exit(1);
            //             break;
            //     }
            //     InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
            //                                         .authFlow(authFlow)
            //                                         .clientId(cmd.getOptionValue("cognito-client-id"))
            //                                         .authParameters(authParams)
            //                                         .build();
            //     InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);
            //     AuthenticationResultType authenticationResult = authResponse.authenticationResult();
            //     CognitoIdentityClient cognitoIdentityClient = CognitoIdentityClient.builder().region(region).build();
            //     GetIdRequest getIdRequest = GetIdRequest.builder()
            //                                 .identityPoolId(cmd.getOptionValue("cognito-identity-pool-id"))
            //                                 .logins(Map.of("cognito-idp." + region.id() + ".amazonaws.com/" + userPoolId, authenticationResult.idToken()))
            //                                 .build();
            //     GetIdResponse getIdResponse = cognitoIdentityClient.getId(getIdRequest);
            //     String identityId = getIdResponse.identityId();
            //     GetCredentialsForIdentityRequest getCredsForIdReq = GetCredentialsForIdentityRequest.builder()
            //                                                          .identityId(identityId)
            //                                                          .logins(Map.of("cognito-idp." + region.id() + ".amazonaws.com/" + userPoolId, authenticationResult.idToken()))
            //                                                          .build();
            //     GetCredentialsForIdentityResponse getCredsForIdResp = cognitoIdentityClient.getCredentialsForIdentity(getCredsForIdReq);
            //     StaticCredentialsProvider staticCredsProvider = new StaticCredentialsProvider.StaticCredentialsProviderBuilder()
            //                                                         .withAccessKeyId​(getCredsForIdResp.credentials().accessKeyId().getBytes())
            //                                                         .withSecretAccessKey​(getCredsForIdResp.credentials().secretKey().getBytes())
            //                                                         .withSessionToken​(getCredsForIdResp.credentials().sessionToken().getBytes())
            //                                                         .build();
            //     connBuilder = connBuilder.withWebsocketCredentialsProvider(staticCredsProvider);
            //
            /*} else*/ if (cmd.hasOption("aws-access-key-id") && cmd.hasOption("aws-secret-key")
                        && cmd.hasOption("aws-session-token")) {
                sigV4Auth = true;
                StaticCredentialsProvider staticCredsProvider = new StaticCredentialsProvider.StaticCredentialsProviderBuilder()
                                                                    .withAccessKeyId​(cmd.getOptionValue("aws-access-key-id").getBytes())
                                                                    .withSecretAccessKey​(cmd.getOptionValue("aws-secret-key").getBytes())
                                                                    .withSessionToken​(cmd.getOptionValue("aws-session-token").getBytes())
                                                                    .build();
                connBuilder = connBuilder.withWebsocketCredentialsProvider(staticCredsProvider);

            } else {
                System.err.println("[ERROR] Missing connection parameters (must provide some combination of \"-c\", \"-k\", \"-K\", \"-q\", \"-A\", \"-Q\", \"--custom-auth-*\", \"--cognito-*\", \"--aws-*\", etc.)");
                System.exit(1);
            }

            tlsCtxOpts = TlsContextOptions.createDefaultClient();

        } else {
            System.err.println("[ERROR] Missing connection parameters (must provide some combination of \"-c\", \"-k\", \"-K\", \"-q\", \"-A\", \"-Q\", \"--custom-auth-*\", \"--cognito-*\", \"--aws-*\", etc.)");
            System.exit(1);
        }

        if (cmd.hasOption("C")) {
            clientId = cmd.getOptionValue("C");
        } else {
            // Generate a unique client ID
            clientId = "DEVICE_" + System.currentTimeMillis();
        }
        System.err.println("[INFO] Using client ID: " + clientId);

        if (cmd.hasOption("w")) {
            // Using MQTT-over-WebSocket
            if (!(customAuth || sigV4Auth)) {
                // https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html#protocol-mapping
                System.err.println("[ERROR] MQTT over WebSocket requires Signature Version 4, AWS/Cognito, or custom authentication");
                System.exit(1);
            }
            connBuilder = connBuilder.withWebsocketSigningRegion​(cmd.getOptionValue("r"));
        } else {
            // Not using WebSockets
            if (sigV4Auth) {
                // https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html#protocol-mapping
                System.err.println("[ERROR] Signature Version 4 authentication is only supported in conjunction with MQTT-over-WebSocket (\"-w\")");
                System.exit(1);
            }
        }

        // Configure the connection
        connBuilder = connBuilder.withConnectionEventCallbacks(connectionCallbacks);
        connBuilder = connBuilder.withClientId(clientId);
        connBuilder = connBuilder.withEndpoint(cmd.getOptionValue("H"));
        if (cmd.hasOption("A")) {
            String certAuthority = Util.getTextFileDataFromOptionalPath(cmd.getOptionValue("A"));
            connBuilder = connBuilder.withCertificateAuthority(certAuthority);
            tlsCtxOpts = tlsCtxOpts.withCertificateAuthority(certAuthority);
        }
        if (cmd.hasOption("u")) {
            connBuilder = connBuilder.withUsername(cmd.getOptionValue("u"));
        }
        if (cmd.hasOption("p")) {
            connBuilder = connBuilder.withPassword(cmd.getOptionValue("p"));
        }
        int portNum = -1;
        if (cmd.hasOption("P")) {
            portNum = ((Number)cmd.getParsedOptionValue("P")).intValue();
            if (portNum < 1 || portNum > 65535) {
                System.err.println("[ERROR] Port number must be in the range 1-65535 (inclusive)");
                System.exit(1);
            }
            connBuilder = connBuilder.withPort((short)portNum);
        }
        if (cmd.hasOption("U")) {
            tlsCtxOpts = tlsCtxOpts.withVerifyPeer​(false);
        }


        // Build
        tlsContext = new ClientTlsContext(tlsCtxOpts);

        if (cmd.hasOption("5")) {
            // @TODO
            throw new UnsupportedOperationException("MQTT5 connections not supported yet");
            //mqtt5ClientConnection = connBuilder.toAwsIotMqtt5ClientBuilder().build();
        } else {
            clientConnection = connBuilder.build();
        }
        connBuilder.close();
    }


    public static void mqttConnect() {
        System.err.println("[INFO] Connecting to " + cmd.getOptionValue("H"));
        if (mqtt5ClientConnection != null) {
            mqtt5ClientConnection.start();
        } else {
            CompletableFuture<Boolean> isCleanConnFuture = clientConnection.connect();
            try {
                Boolean isCleanSession = isCleanConnFuture.get();
                // System.err.println("[INFO] Clean session? " + isCleanSession.toString());
            } catch (ExecutionException | InterruptedException e) {
                System.err.println("[ERROR] Exception connecting: " + e.toString());
                System.exit(2);
            }
        }
    }



    // Extracts known data fields from MQTT topic strings. Note that this method is NOT meant for extracting data from MQTT message payloads.
    public static Map<String, String> extractFieldsFromTopic(String topic) {
        if (topic.equals(AwsIotConstants.MQTT_PING_TOPIC)) {
            return null;
        }
        for (PatternWithNamedGroups p : topicsRegex) 
        { 
            Matcher matcher = p.getPattern().matcher(topic);
            boolean matchFound = matcher.find();
            if (matchFound) {
                List<String> groupNames = p.getGroupNames();
                if (groupNames.size() != matcher.groupCount()) {
                    System.err.println("[WARNING] Mismatch between number of capture group names (" + groupNames.size() + ") and matched group count (" + matcher.groupCount() + ")");
                    continue;
                }
                HashMap<String, String> captures = new HashMap<String, String>();
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    captures.put(groupNames.get(i-1), matcher.group(i));
                }
                return captures;
            }
        }
        if (topic.startsWith(AwsIotConstants.MQTT_RESERVED_TOPIC_PREFIX)) {
            // All AWS-reserved MQTT topics should be matched...
            System.err.println("[WARNING] Failed to extract fields from reserved MQTT topic: " + topic);
        }
        return null;
    }



    // Returns the list of user-specified MQTT topics, or a wildcard topic representing all topics ("#")
    public static List<String> buildMqttTopicList() {
        ArrayList<String> topics = new ArrayList<String>();
        if (topicSubcriptions.isEmpty()) {
            // Use wildcard to subscribe to all topics
            topics.add(AwsIotConstants.MQTT_ALL_TOPICS);
        } else {
            // Subscribe to user-specified topics only
            topics.addAll(topicSubcriptions);
        }
        return topics;
    }



    // Dump all MQTT messages received via subscribed MQTT topics. Runs forever (or until cancelled by the user with Ctrl+C)
    public static void beginMqttDump() throws InterruptedException, ExecutionException {
        final List<String> topics = buildMqttTopicList();
        
        for (final String topic : topics) {
            System.err.println("[INFO] Subscribing to topic for MQTT dump (\"" + topic + "\")");
            CompletableFuture<Integer> subscription = clientConnection.subscribe(topic, QualityOfService.AT_LEAST_ONCE, genericMqttMsgConsumer);
            subscription.exceptionally((Throwable throwable) -> {
                System.err.println("[ERROR] Failed to process message for " + topic + ": " + throwable.toString());
                return -1;
            });
            subscription.get();
        }

        Util.sleepForever();
    }



    // Extract known data fields from subscribed MQTT topics. Runs forever (or until cancelled by the user with Ctrl+C).
    // Note that this only extracts data from the topic itself, and ignores MQTT message payloads.
    public static void beginMqttTopicFieldHarvesting() throws InterruptedException, ExecutionException {
        final List<String> topics = buildMqttTopicList();

        for (final String topic : topics) {
            System.err.println("[INFO] Subscribing to topic for topic field harvesting (\"" + topic + "\")");
            CompletableFuture<Integer> subscription = clientConnection.subscribe(topic, QualityOfService.AT_LEAST_ONCE, topicFieldHarvester);
            subscription.exceptionally((Throwable throwable) -> {
                System.err.println("[ERROR] Failed to process message for " + topic + ": " + throwable.toString());
                return -1;
            });
            subscription.get();
        }
        
        Util.sleepForever();
    }


    // Test whether the AWS IoT service can be used for data exfiltration via arbitrary topics
    public static void testDataExfilChannel() throws InterruptedException, ExecutionException {
        final String timestamp = "" + System.currentTimeMillis();

        ArrayList<String> topics = new ArrayList<String>();
        if (topicSubcriptions.isEmpty()) {
            // By default, use the current epoch timestamp for a unique MQTT topic
            topics.add(timestamp);
        } else {
            topics.addAll(topicSubcriptions);
        }

        final Consumer<MqttMessage> dataExfilConsumer = new Consumer<MqttMessage>() {
            @Override
            public void accept(MqttMessage message) {
                final String payloadStr = new String(message.getPayload(), StandardCharsets.UTF_8).trim();
                String msg = null;
                if (payloadStr.equals(timestamp)) {
                    System.out.println("\n[Data exfiltration] Confirmed data exfiltration channel via topic: " + message.getTopic());
                } else {
                    System.err.println("[WARNING] Unknown data received via data exfiltration channel (topic: " + message.getTopic() + "): " + payloadStr);
                }
            }
        };
        
        // Subscribe to the data exfiltration topic(s)
        for (final String topic : topics) {
            System.err.println("[INFO] Testing data exfiltration via arbitrary topics (using topic: \"" + topic + "\")");
            CompletableFuture<Integer> subscription = clientConnection.subscribe(topic, QualityOfService.AT_LEAST_ONCE, dataExfilConsumer);
            subscription.exceptionally((Throwable throwable) -> {
                System.err.println("[ERROR] Failed to process message for " + topic + ": " + throwable.toString());
                return -1;
            });
            subscription.get();

            // Publish data to the data exfiltration topic
            MqttMessage msg = new MqttMessage(topic, timestamp.getBytes(StandardCharsets.UTF_8), QualityOfService.AT_LEAST_ONCE);
            CompletableFuture<Integer> publication = clientConnection.publish(msg);
            publication.get();
        }

        // Sleep 3 seconds to see if we receive our payload
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ex) {
            System.err.println("[WARNING] Data exfiltration sleep operation was interrupted: " + ex.getMessage());
        }
        
        // Unsubscribe from the data exfiltration topic(s)
        for (final String topic : topics) {
            CompletableFuture<Integer> unsub = clientConnection.unsubscribe(topic);
            unsub.get();
        }
    }


    // Attempts to obtain IAM credentials for the specified role using the client mTLS key pair from an IoT "Thing" (device)
    //
    // Note that the iot:CredentialProvider is a different host/endpoint than the base IoT endpoint; it should have the format:
    // ${random_id}.credentials.iot.${region}.amazonaws.com
    //
    // (The random_id will also be different from the one in the base IoT Core endpoint)
    public static List<Credentials> getIamCredentialsFromDeviceX509(String[] roleAliases, String thingName) {
        // See also:
        //   https://github.com/aws/aws-iot-device-sdk-java-v2/blob/de4e5f3be56c325975674d4e3c0a801392edad96/samples/X509CredentialsProviderConnect/src/main/java/x509credentialsproviderconnect/X509CredentialsProviderConnect.java#L99
        //   https://awslabs.github.io/aws-crt-java/software/amazon/awssdk/crt/auth/credentials/X509CredentialsProvider.html
        //   https://aws.amazon.com/blogs/security/how-to-eliminate-the-need-for-hardcoded-aws-credentials-in-devices-by-using-the-aws-iot-credentials-provider/

        final String endpoint = cmd.getOptionValue("H");
        if (!endpoint.contains("credentials.iot")) {
            System.err.println("[WARNING] Endpoint \"" + endpoint + "\" might not be an AWS IoT credentials provider; are you sure you have the right hostname? (Expected format: \"${random_id}.credentials.iot.${region}.amazonaws.com\")");
        }

        ArrayList<Credentials> discoveredCreds = new ArrayList<Credentials>();

        for (String roleAlias : roleAliases) {
            // // mTLS HTTP client method:
            // String url = "https://" + endpoint + "/role-aliases/" + roleAlias + "/credentials";
            // String data = MtlsHttpClient.mtlsHttpGet(url, cmd.getOptionValue("c"), cmd.getOptionValue("k"), cmd.getOptionValue("A"), true);
            // // Need to add header "x-amzn-iot-thingname: " + thingName
            // System.out.println(data);
            // return null;

            Credentials credentials = null;
            X509CredentialsProvider.X509CredentialsProviderBuilder x509CredsBuilder = new X509CredentialsProvider.X509CredentialsProviderBuilder();
            x509CredsBuilder = x509CredsBuilder.withTlsContext(tlsContext);
            x509CredsBuilder = x509CredsBuilder.withEndpoint​(endpoint);
            x509CredsBuilder = x509CredsBuilder.withRoleAlias(roleAlias);
            x509CredsBuilder = x509CredsBuilder.withThingName(thingName);
            X509CredentialsProvider credsProvider = x509CredsBuilder.build();
            CompletableFuture<Credentials> credsFuture = credsProvider.getCredentials();
            try {
                credentials = credsFuture.get();
                String credsStr = "{\"credentials\":{\"accessKeyId\":\"" + new String(credentials.getAccessKeyId(), StandardCharsets.UTF_8) + "\"";
                credsStr += ",\"secretAccessKey\":\"" + new String(credentials.getSecretAccessKey(), StandardCharsets.UTF_8) + "\"";
                credsStr += ",\"sessionToken\":\"" + new String(credentials.getSessionToken(), StandardCharsets.UTF_8) + "\"}}";
                System.out.println(credsStr);
                discoveredCreds.add(credentials);
            } catch (ExecutionException | InterruptedException  ex) {
                System.err.println("[ERROR] Failed to obtain credentials from X509 (role=\"" + roleAlias + "\"; thingName=\"" + thingName + "\"): " + ex.getMessage());
            }
            
            credsProvider.close();
        }

        return discoveredCreds;
    }


    public static void getDeviceShadow(String thingName, String shadowName) {
        // https://docs.aws.amazon.com/iot/latest/developerguide/device-shadow-rest-api.html#API_GetThingShadow
        // https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/services/iotdataplane/IotDataPlaneClient.html
        // https://dzone.com/articles/execute-mtls-calls-using-java
        //
        // Example HTTP request (mTLS required):
        //
        //   GET /things/<thingName>/shadow?name=<shadowName> HTTP/1.1
        //   Host: <instance>.iot.<region>.amazonaws.com:8443
        //
        // Note: Shadow name is optional (null name = classic device shadow)
        String url = "https://" + cmd.getOptionValue("H") + ":" + AwsIotConstants.AWS_IOT_REST_API_PORT + "/things/" + thingName + "/shadow" + (shadowName == null ? "" : "?name="+shadowName);
        String data = MtlsHttpClient.mtlsHttpGet(url, cmd.getOptionValue("c"), cmd.getOptionValue("k"), cmd.getOptionValue("A"), true);
        System.out.println(data);
    }


    public static void getNamedShadows(String thingName) {
        // @TODO
        // https://docs.aws.amazon.com/iot/latest/developerguide/device-shadow-rest-api.html#API_ListNamedShadowsForThing
        // https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/services/iotdataplane/IotDataPlaneClient.html
        // https://dzone.com/articles/execute-mtls-calls-using-java
        //
        // Example HTTP request (mTLS required):
        //
        //   GET /api/things/shadow/ListNamedShadowsForThing/<thingName>?maxResults=200&nextToken= HTTP/1.1
        //   Host: <instance>.iot.<region>.amazonaws.com:8443
        String url = "https://" + cmd.getOptionValue("H") + ":" + AwsIotConstants.AWS_IOT_REST_API_PORT + "/api/things/shadow/ListNamedShadowsForThing/" + thingName + "?maxResults=200"; //+"&nextToken=";
        String data = MtlsHttpClient.mtlsHttpGet(url, cmd.getOptionValue("c"), cmd.getOptionValue("k"), cmd.getOptionValue("A"), true);
        // @TODO: Iterate through all pages of named shadows
        System.out.println(data);
    }


    public static void getRetainedMqttMessages() {
        // @TODO
        // https://docs.aws.amazon.com/iot/latest/apireference/API_iotdata_ListRetainedMessages.html
        // https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/services/iotdataplane/IotDataPlaneClient.html
        // https://dzone.com/articles/execute-mtls-calls-using-java
        //
        // Example HTTP requests (mTLS required):
        //
        //   GET /retainedMessage?maxResults=200&nextToken= HTTP/1.1
        //   Host: <instance>.iot.<region>.amazonaws.com:8443
        //
        //   GET /retainedMessage/<topic> HTTP/1.1
        //   Host: <instance>.iot.<region>.amazonaws.com:8443
        String url = "https://" + cmd.getOptionValue("H") + ":" + AwsIotConstants.AWS_IOT_REST_API_PORT + "/retainedMessage?maxResults=200"; //+"&nextToken=";
        String data = MtlsHttpClient.mtlsHttpGet(url, cmd.getOptionValue("c"), cmd.getOptionValue("k"), cmd.getOptionValue("A"), true);
        // @TODO: Iterate through all pages of retained messages
        // @TODO: Get message bodies for all retained message topics
        System.out.println(data);
    }


    // https://docs.aws.amazon.com/iot/latest/developerguide/jobs-mqtt-api.html
    public static void getPendingJobs() throws InterruptedException, ExecutionException {
        final String thingName = cmd.hasOption("t") ? cmd.getOptionValue("t") : clientId;
        final String topic = "$aws/things/" + thingName + "/jobs/get";
        final String topicAccepted = topic + "/accepted";
        final String topicRejected = topic + "/rejected";
        final String message = "{}";


        CompletableFuture<Integer> subAccept = clientConnection.subscribe(topicAccepted, QualityOfService.AT_LEAST_ONCE, genericMqttMsgConsumer);
        subAccept.exceptionally((Throwable throwable) -> {
            System.err.println("[ERROR] Failed to process message for " + topicAccepted + ": " + throwable.toString());
            return -1;
        });
        subAccept.get();
        CompletableFuture<Integer> subReject = clientConnection.subscribe(topicRejected, QualityOfService.AT_LEAST_ONCE, genericMqttMsgConsumer);
        subReject.exceptionally((Throwable throwable) -> {
            System.err.println("[ERROR] Failed to process message for " + topicRejected + ": " + throwable.toString());
            return -1;
        });
        subReject.get();

        MqttMessage msg = new MqttMessage(topic, message.getBytes(StandardCharsets.UTF_8), QualityOfService.AT_LEAST_ONCE);
        CompletableFuture<Integer> publication = clientConnection.publish(msg);
        publication.get();

        // Sleep 3 seconds to see if we receive our payload
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ex) {
            System.err.println("[WARNING] Get pending jobs sleep operation was interrupted: " + ex.getMessage());
        }
        
        // Unsubscribe from the accept/reject topic(s)
        CompletableFuture<Integer> unsubAccept = clientConnection.unsubscribe(topicAccepted);
        unsubAccept.get();
        CompletableFuture<Integer> unsubReject = clientConnection.unsubscribe(topicRejected);
        unsubReject.get();
    }


    public static void runMqttScript(String scriptFilePath) throws IOException, InterruptedException, ExecutionException {
        final String tag = "[MQTT Script] ";
        final int maxLogMsgSize = 80;
        System.err.println(tag + "Executing script: " + scriptFilePath);
        List<MqttScript.Instruction> instructions = MqttScript.parseFromFile(scriptFilePath);

        for (int i = 0; i < instructions.size(); i++) {
            MqttScript.Instruction instr = instructions.get(i);

            if (instr.getOp().equals(MqttScript.Instruction.OP_PUBLISH)) {
                String logMsg = instr.toString();
                if (logMsg.length() > maxLogMsgSize) {
                    logMsg = logMsg.substring(0, maxLogMsgSize) + "...";
                }
                System.err.println(tag + logMsg);
                MqttMessage msg = new MqttMessage(instr.getTopic(), instr.getPayload(), QualityOfService.AT_LEAST_ONCE);
                CompletableFuture<Integer> publication = clientConnection.publish(msg);
                publication.get();

            } else if (instr.getOp().equals(MqttScript.Instruction.OP_SUBSCRIBE)) {
                System.err.println(tag + instr.toString());
                final String topic = instr.getTopic();
                CompletableFuture<Integer> subscription = clientConnection.subscribe(topic, QualityOfService.AT_LEAST_ONCE, genericMqttMsgConsumer);
                subscription.exceptionally((Throwable throwable) -> {
                    System.err.println("[ERROR] Failed to process message for " + topic + ": " + throwable.toString());
                    return -1;
                });
                subscription.get();

            } else if (instr.getOp().equals(MqttScript.Instruction.OP_UNSUBSCRIBE)) {
                System.err.println(tag + instr.toString());
                CompletableFuture<Integer> unsub = clientConnection.unsubscribe(instr.getTopic());
                unsub.get();

            } else if (instr.getOp().equals(MqttScript.Instruction.OP_SLEEP)) {
                System.err.println(tag + instr.toString());
                Util.sleep(instr.getDelay());

            } else {
                System.err.println("[WARNING] Encountered unknown MQTT script instruction: " + instr.getOp());
            }
        }

        Util.sleepForever();
    }

}