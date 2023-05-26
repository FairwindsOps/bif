# BIF - The Fairwinds Base Image Finder Client

This utility interacts with the Fairwinds BIF-Server to find base images and report on their vulnerabilities.

## Usage

### Request a Token

First, you must request an API token to use with the base image finder. You can do this via the cli:

```
bif request-token
# Follow the prompt to enter your email address
```

You will receive your token via email

### Extract Layers Using Skopeo and Find Base Image

```
bif find --image-layers $(skopeo inspect docker://us-docker.pkg.dev/fairwinds-ops/oss/polaris:7.0.0 | jq .Layers[] -rc)

Input:  [sha256:2408cc74d12b6cd092bb8b516ba7d5e290f485d3eb9672efc00f0583730179e8]

   BASE IMAGE   | LAST SCAN  |      CVE       | SEVERITY | CVSS |    FIXED IN
----------------+------------+----------------+----------+------+-----------------
  alpine:3.16.0 | 2023-02-28 | CVE-2022-2097  | MEDIUM   | 5.30 | 3.17.3, 3.16.5
                |            | CVE-2022-30065 | HIGH     | 7.80 | 3.17.3, 3.16.5
                |            | CVE-2022-37434 | CRITICAL | 9.80 | 3.17.3, 3.16.5
                |            | CVE-2022-4304  | MEDIUM   | 5.90 | 3.17.3, 3.16.5
                |            | CVE-2022-4450  | HIGH     | 7.50 | 3.17.3, 3.16.5
                |            | CVE-2023-0215  | HIGH     | 7.50 | 3.17.3, 3.16.5
                |            | CVE-2023-0286  | HIGH     | 7.40 | 3.17.3, 3.16.5
```

### Use BIF with a publicly-available image
```
bif find --image us-docker.pkg.dev/fairwinds-ops/oss/polaris:7.0.0

Input: us-docker.pkg.dev/fairwinds-ops/oss/polaris 7.0.0

   BASE IMAGE   | LAST SCAN  |      CVE       | SEVERITY | CVSS |    FIXED IN
----------------+------------+----------------+----------+------+-----------------
  alpine:3.16.0 | 2023-02-28 | CVE-2022-2097  | MEDIUM   | 5.30 | 3.17.3, 3.16.5
                |            | CVE-2022-30065 | HIGH     | 7.80 | 3.17.3, 3.16.5
                |            | CVE-2022-37434 | CRITICAL | 9.80 | 3.17.3, 3.16.5
                |            | CVE-2022-4304  | MEDIUM   | 5.90 | 3.17.3, 3.16.5
                |            | CVE-2022-4450  | HIGH     | 7.50 | 3.17.3, 3.16.5
                |            | CVE-2023-0215  | HIGH     | 7.50 | 3.17.3, 3.16.5
                |            | CVE-2023-0286  | HIGH     | 7.40 | 3.17.3, 3.16.5
```

## Troubleshooting

If you run into issues, you can try adding debug logging with the `--debug` flag. If you have further issues, please reach out in the community slack or file a github issue.