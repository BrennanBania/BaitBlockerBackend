FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies with better error handling
RUN npm install --production && \
    npm cache clean --force

# Copy application code
COPY app.js .

# Expose port
EXPOSE 8080

# Set environment variables
ENV PORT=8080
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/api/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})" || exit 1

# Start application
CMD ["npm", "start"]
