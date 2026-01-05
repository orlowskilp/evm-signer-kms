#!/bin/bash

# Marks the workspace root directory as a safe directory for git
git config --global --add safe.directory $(pwd)

# Suspend git's message about moving to `main` as the default branch name
git config --global init.defaultBranch master

# Allow direnv to load environment variables every time a new shell is started
echo -e "\ndirenv allow ${CONTAINER_WORKSPACE_FOLDER}" >> ~/.bashrc