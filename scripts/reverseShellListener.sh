#!/bin/bash

while true; do
    nc -lvnp 9876
    echo "Client disconnected, restarting..."
done
