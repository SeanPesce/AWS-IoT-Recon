# AWS IoT Recon  

**Author: Sean Pesce**  


## Overview  

Security assessment tool for enumeration of [AWS IoT Core](https://aws.amazon.com/iot-core/)
(data plane) using compromised IoT device keys.  


## Disclaimer  

This tool should only be used in testing environments with the goal of securing product implementations.
The author of this tool does not endorse the use of this tool against real-world production environments
without prior permission from the owner of the target instance(s). Additionally, the use of this tool against
real-world implementations may trigger detection/alert mechanisms in [IoT Device Defender](https://aws.amazon.com/iot-device-defender/),
resulting in client key disablement/revocation and/or further repercussions (legal or otherwise).  


## Building  

To compile this project, make sure you have a [JDK](https://openjdk.org/) and
[Apache Maven](https://maven.apache.org/) installed. Then, simply run the following command:  

```
mvn package
```

The resulting executable JAR file will be in the `target/` directory.  


## Built With  

 * [AWS IoT Device SDK for Java v2](https://github.com/aws/aws-iot-device-sdk-java-v2)  
 * [Apache Maven](https://github.com/apache/maven)  


## Related Resources for Further Information  

 * [AWS Skill Builder - Deep Dive into AWS IoT Authentication and Authorization](https://explore.skillbuilder.aws/learn/course/external/view/elearning/5667/deep-dive-into-aws-iot-authentication-and-authorization)
 * [AWS Skill Builder - Introduction to IoT Device Defender](https://explore.skillbuilder.aws/learn/course/310/play/25424/introduction-to-iot-device-defender)


## Contact  

If you find any bugs, please open a [GitHub issue](https://github.com/SeanPesce/AWS-IoT-Recon/issues/new).  


## License  

[GNU General Public License v2.0](LICENSE)  


---------------------------------------------

For unrelated inquiries and/or information about me, visit my **[personal website](https://SeanPesce.github.io)**.  


