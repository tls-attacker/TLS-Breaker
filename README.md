# TLS-Breaker

A tool collection of various attacks on TLS based on TLS-Attacker

## Docker Support

The `tls-breaker-docker` directory contains Docker configuration for running TLS-Breaker in a containerized environment.

1. Building the Docker Image:
```sh
cd tls-breaker-docker
docker build -t tls-breaker-docker .
```

2. Running the Container:
```sh
cd tls-breaker-docker
# The script will:
# * Start an interactive bash shell in the container
# * Mount ./app directory to /app (for compiled JARs)
# * Mount ./data directory to /data (for additional files)
# * Auto-remove container after exit
bash run.sh
```

3. Usage Example:
```sh
# Inside container:
java -jar /app/heartbleed-1.0.1.jar --help
java -jar /app/bleichenbacher-1.0.1.jar --help
```
