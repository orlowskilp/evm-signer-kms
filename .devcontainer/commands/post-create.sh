#!/bin/bash

# Marks the workspace root directory as a safe directory for git
git config --global --add safe.directory $(pwd)