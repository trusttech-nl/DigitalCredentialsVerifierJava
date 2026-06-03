# Digital Credentials Verifier

Java library for verifying digital credentials.

## Requirements

* Java 17
* Maven 3.8+

## Installation

## Build from source

Clone repository and install into local Maven repository:

```bash
mvn clean install
```

After that, artifact will be available in:

```
~/.m2/repository/nl/trusttech/digital-credentials-verifier/
```
### Add dependency to you project

```xml
<dependency>
    <groupId>nl.trusttech</groupId>
    <artifactId>digital-credentials-verifier</artifactId>
    <version>1.0-SNAPSHOT</version>
    <classifier>shaded</classifier>
</dependency>
```