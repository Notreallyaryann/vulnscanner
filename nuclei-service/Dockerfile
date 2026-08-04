# Stage 1: Get official Nuclei binary
FROM projectdiscovery/nuclei:latest AS nuclei_bin

# Stage 2: Node.js runtime microservice
FROM node:20-slim

# Install system dependencies (ca-certificates, git for template updates,
# findutils for the `find` command used by resolveTemplateDir() at runtime)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    curl \
    findutils \
    && rm -rf /var/lib/apt/lists/*

# Copy nuclei binary from official container
COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy application source code
COPY . .

# Explicitly set HOME so template download/read paths match at build AND run time
ENV HOME=/root

# Optional but recommended while you're debugging empty-scan issues —
# turn this off (or unset) once things are confirmed working.
ENV DEBUG_SCAN=true

# Download initial nuclei templates during image build so scans run instantly.
RUN nuclei -update-templates

# Fail the build if templates didn't actually land
RUN TEMPLATE_COUNT=$(find /root/nuclei-templates -name "*.yaml" | wc -l) && \
    echo "Nuclei templates downloaded: $TEMPLATE_COUNT" && \
    if [ "$TEMPLATE_COUNT" -lt 100 ]; then \
        echo "ERROR: Too few templates ($TEMPLATE_COUNT) — build likely failed silently." && exit 1; \
    fi

EXPOSE 3002

CMD ["npm", "start"]
