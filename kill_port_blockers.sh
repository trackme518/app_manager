#!/usr/bin/env bash

# kill comfyUI
sudo lsof -t -i:8188 | xargs -r kill -9
# kill Orchestrator manager server
sudo lsof -t -i:9999 | xargs -r kill -9