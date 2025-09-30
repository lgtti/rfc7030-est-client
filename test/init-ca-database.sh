#!/bin/bash

# Initialize CA database if it doesn't exist
CA_DB_DIR="/etc/est/database"

if [ ! -f "$CA_DB_DIR/index.txt" ]; then
    echo "Initializing CA database..."
    
    # Create database files
    echo "01" > "$CA_DB_DIR/serial"
    echo "01" > "$CA_DB_DIR/crlnumber"
    touch "$CA_DB_DIR/index.txt"
    
    # Create newcerts directory
    mkdir -p "$CA_DB_DIR/newcerts"
    
    echo "CA database initialized successfully."
else
    echo "CA database already exists."
fi
