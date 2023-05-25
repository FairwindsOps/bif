FROM alpine:3.18

LABEL org.opencontainers.image.authors="FairwindsOps, Inc." \
      org.opencontainers.image.vendor="FairwindsOps, Inc." \
      org.opencontainers.image.title="bif" \
      org.opencontainers.image.description="BIF is a cli to find base images and associated vulnerabilities" \
      org.opencontainers.image.documentation="https://bif.docs.fairwinds.com/" \
      org.opencontainers.image.source="https://github.com/FairwindsOps/bif" \
      org.opencontainers.image.url="https://github.com/FairwindsOps/bif" \
      org.opencontainers.image.licenses="Apache License 2.0"

USER nobody
COPY bif /

ENTRYPOINT ["/bif"]
