# BIF - The Fairwinds Base Image Finder

This utility interacts with the Fairwinds BIF-Server to find base images and report on their vulnerabilities.

## Usage

### Request a Token

First, you must request an API token to use with the base image finder. You can do this via the cli:

```
bif request-token
# Follow the prompt to enter your email address
```

You will receive your token via email

### Use the Token

```
bif find <image>

# Lots of JSON output right now
```