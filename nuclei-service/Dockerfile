# Stage 1: Get official Nuclei binary
FROM projectdiscovery/nuclei:latest AS nuclei_bin

# Stage 2: Node.js runtime microservice
FROM node:20-slim

# Install system dependencies (ca-certificates, git for template updates)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy nuclei binary from official container
COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

# Copy package files and install production dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy application source code
COPY . .

# Download initial nuclei templates during image build so scans run instantly
RUN nuclei -update-templates || true

EXPOSE 3002

CMD ["npm", "start"]
