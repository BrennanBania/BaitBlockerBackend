# BaitBlocker Backend API

Simple Node.js/Express API for BaitBlocker Chrome extension to interact with Google Cloud SQL database.

## Setup

### Prerequisites
- Node.js 18+
- Google Cloud SQL MySQL instance
- Docker (for deployment)

### Local Development

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Create `.env` file** (copy from `.env.example`)
   ```bash
   cp .env.example .env
   ```

3. **Configure environment variables**
   ```
   DB_HOST=your-cloud-sql-host
   DB_USER=root
   DB_PASSWORD=your-password
   DB_NAME=baitblocker
   DB_PORT=3306
   ```

4. **Run the server**
   ```bash
   npm start          # Production
   npm run dev        # Development with nodemon
   ```

The API will be available at `http://localhost:3000`

## API Endpoints

### Health Check
```
GET /api/health
```
Returns: `{ status: 'ok', message: '...' }`

### Save Threat Analysis
```
POST /api/threats
Content-Type: application/json

{
  "gmail_email_id": "message-id",
  "threat_level": "high",           // phishing, spam, suspicious, safe
  "threat_score": 85,                // 0-100
  "reasons": ["Known phishing domain"],
  "analysis_details": { "gemini_score": 85 }
}
```

### Get Threats for User
```
GET /api/threats?email=user@example.com&limit=50&offset=0
```
Returns: `{ threats: [...], count: N }`

### Get Threat by ID
```
GET /api/threats/:id
```

### Delete Threat
```
DELETE /api/threats/:id
```

## Database Schema

Required MySQL table:
```sql
CREATE TABLE EmailThreats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  gmail_email_id VARCHAR(255) NOT NULL,
  threat_level VARCHAR(50),
  threat_score INT,
  reasons JSON,
  analysis_details JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (gmail_email_id)
);
```

## Deployment to Cloud Run

### 1. Build Docker image
```bash
docker build -t baitblocker-api .
```

### 2. Push to Google Container Registry
```bash
docker tag baitblocker-api gcr.io/YOUR_PROJECT_ID/baitblocker-api
docker push gcr.io/YOUR_PROJECT_ID/baitblocker-api
```

### 3. Deploy to Cloud Run
```bash
gcloud run deploy baitblocker-api \
  --image gcr.io/YOUR_PROJECT_ID/baitblocker-api \
  --platform managed \
  --region us-central1 \
  --set-env-vars DB_HOST=your-cloud-sql-host,DB_USER=root,DB_PASSWORD=your-password,DB_NAME=baitblocker \
  --allow-unauthenticated
```

After deployment, you'll get a URL like: `https://baitblocker-api-xyz.run.app`

## Notes

- All database credentials should be stored in Cloud Run environment variables or Cloud Secret Manager
- Ensure Cloud SQL is configured to accept connections from Cloud Run
- The API uses connection pooling for efficiency
- Requests include CORS support for the extension
