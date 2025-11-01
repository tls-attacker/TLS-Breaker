# TLS-Breaker

A tool collection of various attacks on TLS based on TLS-Attacker

## Building and running

These tools require Java 14.

You should be able to build the tools using an newer version of Java.
Build the tools using `mvn clean package` (you might need the argument `-Dspotless.apply.skip=true`).

To run the tools you can create an Dockerfile, e.g. for _heartbleed_:

```dockerfile
FROM adoptopenjdk/openjdk14

WORKDIR /apps
COPY apps /apps

ENTRYPOINT ["java", "-jar", "heartbleed-1.0.1.jar"]
```

Then build and run it using:

```bash
docker build --tag 'heartbleed' .
docker run -it 'heartbleed' -help
```