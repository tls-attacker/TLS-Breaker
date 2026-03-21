#!/bin/bash

# -i: keep STDIN open, -t: allocate a tty, --rm: remove container after exit
# bind-mount local ./app into container at /app (overwrite image files if mounted)
# bind-mount local ./data into container at /data for access to other files
# image name to run
# command to execute in the container (start an interactive shell)
docker run -it --rm \
  -v $(pwd)/app:/app \
  -v $(pwd)/data:/data \
  tls-breaker-docker \
  bash
