// Author: Sean Pesce
//
// References:
//   https://docs.aws.amazon.com/iot/latest/developerguide/

package com.seanpesce.aws.iot;

import com.seanpesce.regex.PatternWithNamedGroups;

import java.util.Arrays;
import java.util.List;


public class AwsIotConstants {

    public static final String PROJECT_TITLE = "[AWS IoT Core Data Plane Enumeration Tool by Sean Pesce]";

    public static final String ACTION_MQTT_DUMP = "mqtt-dump";
    public static final String ACTION_MQTT_TOPIC_FIELD_HARVEST = "mqtt-topic-field-harvest";
    public static final String ACTION_IAM_CREDS = "iam-credentials";
    public static final String ACTION_MQTT_DATA_EXFIL = "mqtt-data-exfil";
    public static final String ACTION_GET_SHADOW = "get-device-shadow";
    public static final String ACTION_LIST_NAMED_SHADOWS = "list-named-shadows";
    public static final String ACTION_LIST_RETAINED_MQTT_MESSAGES = "list-retained-mqtt-messages";
    public static final List<String> CLI_ACTIONS = Arrays.asList(new String[]{ACTION_MQTT_DUMP, ACTION_MQTT_TOPIC_FIELD_HARVEST, ACTION_IAM_CREDS, ACTION_MQTT_DATA_EXFIL, ACTION_GET_SHADOW, ACTION_LIST_NAMED_SHADOWS, ACTION_LIST_RETAINED_MQTT_MESSAGES});
    public static final String CLI_AUTH_ARG = "(Auth option) ";
    
    public static final short AWS_IOT_REST_API_PORT = 8443;
    public static final String MQTT_ALL_TOPICS = "#";
    public static final String MQTT_RESERVED_TOPIC_PREFIX = "$aws";
    public static final String MQTT_PING_TOPIC = "mqtt_ping";


    // https://docs.aws.amazon.com/iot/latest/developerguide/reserved-topics.html
    public static final PatternWithNamedGroups[] RESERVED_TOPICS_REGEX = {
        PatternWithNamedGroups.compile("^\\$aws/device_location/(?<thingName>[^/]+)/get_position_estimate$"),
        PatternWithNamedGroups.compile("^\\$aws/device_location/(?<thingName>[^/]+)/get_position_estimate/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/device_location/(?<thingName>[^/]+)/get_position_estimate/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/events/certificates/registered/(?<caCertificateId>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/events/presence/connected/(?<clientId>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/events/presence/disconnected/(?<clientId>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/events/subscriptions/subscribed/(?<clientId>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/events/subscriptions/unsubscribed/(?<clientId>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thing/(?<thingName>[^/]+)/created$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thing/(?<thingName>[^/]+)/updated$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thing/(?<thingName>[^/]+)/deleted$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroup/(?<thingGroupName>[^/]+)/created$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroup/(?<thingGroupName>[^/]+)/updated$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroup/(?<thingGroupName>[^/]+)/deleted$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingType/(?<thingTypeName>[^/]+)/created$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingType/(?<thingTypeName>[^/]+)/updated$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingType/(?<thingTypeName>[^/]+)/deleted$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingTypeAssociation/thing/(?<thingName>[^/]+)/(?<thingTypeName>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroupMembership/thingGroup/(?<thingGroupName>[^/]+)/thing/(?<thingName>[^/]+)/added$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroupMembership/thingGroup/(?<thingGroupName>[^/]+)/thing/(?<thingName>[^/]+)/removed$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroupHierarchy/thingGroup/(?<parentThingGroupName>[^/]+)/childThingGroup/(?<childThingGroupName>[^/]+)/added$"),
        PatternWithNamedGroups.compile("^\\$aws/events/thingGroupHierarchy/thingGroup/(?<parentThingGroupName>[^/]+)/childThingGroup/(?<childThingGroupName>[^/]+)/removed$"),
        PatternWithNamedGroups.compile("^\\$aws/provisioning-templates/(?<templateName>[^/]+)/provision/(?<payloadFormat>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/provisioning-templates/(?<templateName>[^/]+)/provision/(?<payloadFormat>[^/]+)/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/provisioning-templates/(?<templateName>[^/]+)/provision/(?<payloadFormat>[^/]+)/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/rules/(?<ruleName>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/sitewise/asset-models/(?<assetModelId>[^/]+)/assets/(?<assetId>[^/]+)/properties/(?<propertyId>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/defender/metrics/(?<payloadFormat>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/defender/metrics/(?<payloadFormat>[^/]+)/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/defender/metrics/(?<payloadFormat>[^/]+)/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/get$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/get/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/get/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/start-next$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/start-next/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/start-next/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/(?<jobId>[^/]+)/get$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/(?<jobId>[^/]+)/get/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/(?<jobId>[^/]+)/get/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/(?<jobId>[^/]+)/update$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/(?<jobId>[^/]+)/update/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/(?<jobId>[^/]+)/update/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/notify$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/jobs/notify-next$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/tunnels/notify$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/delete$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/delete/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/delete/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/get$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/get/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/get/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/update$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/update/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/update/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/update/delta$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/update/documents$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/delete$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/delete/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/delete/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/get$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/get/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/get/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/update$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/update/accepted$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/update/rejected$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/update/delta$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/shadow/name/(?<shadowName>[^/]+)/update/documents$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/streams/(?<streamId>[^/]+)/data/(?<payloadFormat>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/streams/(?<streamId>[^/]+)/get/(?<payloadFormat>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/streams/(?<streamId>[^/]+)/description/(?<payloadFormat>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/streams/(?<streamId>[^/]+)/describe/(?<payloadFormat>[^/]+)$"),
        PatternWithNamedGroups.compile("^\\$aws/things/(?<thingName>[^/]+)/streams/(?<streamId>[^/]+)/rejected/(?<payloadFormat>[^/]+)$")
    };

}
