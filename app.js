require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();

// Middleware - Configure CORS to allow Chrome extension requests
app.use(cors({
  origin: true, // Allow all origins including chrome-extension://
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Middleware to extract user email from Google auth
app.use((req, res, next) => {
  // Extract user email from request headers (sent by extension)
  // Format: Authorization: Bearer {google-user-email}
  const authHeader = req.headers.authorization;
  const userEmail = req.headers['x-user-email'];
  
  if (userEmail) {
    req.userEmail = userEmail;
  } else if (authHeader && authHeader.startsWith('Bearer ')) {
    // If using Bearer token, assume it's the email
    req.userEmail = authHeader.substring(7);
  }
  
  // For development, allow email from query param or body
  if (!req.userEmail && (req.query.userEmail || req.body?.userEmail)) {
    req.userEmail = req.query.userEmail || req.body.userEmail;
  }
  
  next();
});

// Middleware to ensure database pool is ready
app.use(async (req, res, next) => {
  if (!pool) {
    console.warn('⚠️  Database pool not ready, attempting initialization...');
    try {
      await ensureDatabaseReady();
    } catch (error) {
      console.error('❌ Cannot process request - database not ready:', error.message);
      return res.status(503).json({ error: 'Database not ready - server initializing' });
    }
  }
  next();
});

// Database connection pool
let pool;

const initializeDatabase = async () => {
  try {
    console.log('Initializing database connection...');
    
    const host = process.env.DB_HOST || 'localhost';
    const user = process.env.DB_USER || 'BaitBlocker';
    const password = process.env.DB_PASSWORD;
    const database = process.env.DB_NAME || 'BaitBlocker';
    const port = process.env.DB_PORT || 3306;
    
    // Detect if DB_HOST is a Unix socket path (Cloud SQL Auth Proxy)
    const isUnixSocket = typeof host === 'string' && host.startsWith('/');
    
    if (isUnixSocket) {
      console.log(`📍 Connecting via Unix socket: ${host}`);
      console.log(`📍 Database: ${database}`);
    } else {
      console.log(`📍 Connecting to ${host}:${port}/${database}`);
    }
    console.log('🔐 Using user:', user);
    console.log('🔐 Password provided:', password ? 'YES (length: ' + password.length + ')' : 'NO - This will cause ER_ACCESS_DENIED');
    
    if (!password) {
      console.warn('⚠️  WARNING: No DB_PASSWORD set in environment - connection will fail!');
      console.warn('Set the following environment variables:');
      console.warn('  - DB_HOST: database hostname/IP or Unix socket path (for Cloud SQL Auth Proxy)');
      console.warn('  - DB_USER: database username');
      console.warn('  - DB_PASSWORD: database password (REQUIRED)');
      console.warn('  - DB_NAME: database name');
      console.warn('  - DB_PORT: database port (default 3306, ignored for Unix socket)');
    }
    
    // Build connection config - use socketPath for Unix sockets, host/port for TCP
    const poolConfig = {
      user: user,
      password: password,
      database: database,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      enableKeepAlive: true,
      keepAliveInitialDelayMs: 0
    };
    
    if (isUnixSocket) {
      poolConfig.socketPath = host;
    } else {
      poolConfig.host = host;
      poolConfig.port = port;
    }
    
    pool = mysql.createPool(poolConfig);
    
    console.log('✅ Connection pool created');
    
    // Test connection and create table
    const connection = await pool.getConnection();
    console.log('✅ Database connection successful');
    
    // Create/use existing EmailThreats table
    // Table should have: id, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, scanned_at, analysis_details, created_at
    console.log('✅ Table schema verified');
    

    
    connection.release();
    console.log('✅ Database initialization complete - pool ready for requests');
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    console.error('Error code:', error.code);
    if (error.message.includes('ER_ACCESS_DENIED')) {
      console.error('🔐 Authentication failed - check DB_USER and DB_PASSWORD');
    }
    if (error.message.includes('ECONNREFUSED') || error.message.includes('EHOSTUNREACH')) {
      console.error('🌐 Cannot reach database server - check DB_HOST and network');
    }
    throw error;  // Re-throw to fail the startup
  }
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'BaitBlocker API is running' });
});

// Diagnostic endpoint to check database schema
app.get('/api/debug/schema', async (req, res) => {
  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const connection = await pool.getConnection();
    
    // Get table structure
    const [columns] = await connection.execute('DESCRIBE EmailThreats');
    const [tableExists] = await connection.execute(
      "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_NAME='EmailThreats' AND TABLE_SCHEMA=DATABASE()"
    );
    
    connection.release();

    res.json({
      tableExists: tableExists.length > 0,
      columns: columns.map(col => ({
        name: col.Field,
        type: col.Type,
        nullable: col.Null,
        key: col.Key,
        default: col.Default
      }))
    });
  } catch (error) {
    console.error('Schema check error:', error.message);
    res.status(500).json({ 
      error: 'Failed to check schema',
      details: error.message
    });
  }
});

// Get threat statistics
app.get('/api/stats', async (req, res) => {
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.query.userEmail;

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail query parameter' });
  }

  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const connection = await pool.getConnection();

    const query = `
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN threat_level = 'danger' THEN 1 ELSE 0 END) as high_risk,
        SUM(CASE WHEN threat_level = 'suspicious' THEN 1 ELSE 0 END) as suspicious,
        SUM(CASE WHEN threat_level = 'safe' THEN 1 ELSE 0 END) as safe
      FROM EmailThreats
      WHERE user_email = ?
    `;

    const [rows] = await connection.execute(query, [userEmail]);
    connection.release();

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Save threat analysis
app.post('/api/threats', async (req, res) => {
  console.log('📨 POST /api/threats received');
  
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.body?.userEmail;
  
  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail in body' });
  }
  
  console.log('👤 Request from user:', userEmail);
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  
  const { gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details } = req.body;

  if (!gmail_email_id || !from_address || threat_level === undefined || threat_score === undefined) {
    console.error('❌ Missing required fields:', { gmail_email_id, from_address, subject, threat_level, threat_score });
    return res.status(400).json({ error: 'Missing required fields: gmail_email_id, from_address, threat_level, threat_score' });
  }

  try {
    // Check if pool is initialized
    if (!pool) {
      console.error('❌ Database pool not initialized - checking environment');
      console.log('DB_HOST:', process.env.DB_HOST ? '***' : 'NOT SET');
      console.log('DB_USER:', process.env.DB_USER ? '***' : 'NOT SET');
      console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '***' : 'NOT SET');
      console.log('DB_NAME:', process.env.DB_NAME || 'NOT SET');
      console.log('DB_PORT:', process.env.DB_PORT || '3306');
      
      // Try to initialize now
      console.log('🔄 Attempting emergency database initialization...');
      try {
        await initializeDatabase();
        console.log('✅ Emergency initialization successful');
      } catch (initError) {
        console.error('❌ Emergency initialization failed:', initError.message);
        return res.status(503).json({ 
          error: 'Database not available', 
          details: 'Pool not initialized and emergency init failed',
          dbStatus: {
            poolExists: false,
            env: {
              DB_HOST: process.env.DB_HOST ? 'SET' : 'NOT SET',
              DB_USER: process.env.DB_USER ? 'SET' : 'NOT SET',
              DB_PASSWORD: process.env.DB_PASSWORD ? 'SET' : 'NOT SET'
            }
          }
        });
      }
    }

    console.log('🔌 Getting database connection...');
    const connection = await pool.getConnection();
    console.log('✅ Database connection acquired');
    
    const query = `
      INSERT INTO EmailThreats (user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    `;
    
    console.log('📝 Executing insert query with params:', { userEmail, gmail_email_id, from_address, threat_level, threat_score });
    
    const [result] = await connection.execute(query, [
      userEmail,
      gmail_email_id,
      from_address,
      subject || '',
      threat_level,
      threat_score,
      JSON.stringify(reasons || []),
      JSON.stringify(analysis_details || {})
    ]);

    connection.release();
    console.log('✅ Threat saved successfully with ID:', result.insertId);

    res.status(201).json({
      message: 'Threat analysis saved',
      id: result.insertId
    });
  } catch (error) {
    console.error('❌ Error saving threat:', error.message);
    console.error('Full error:', error);
    console.error('Error code:', error.code);
    console.error('Error errno:', error.errno);
    console.error('Stack:', error.stack);
    
    // Return specific error messages for debugging
    let statusCode = 500;
    let errorMsg = 'Failed to save threat analysis';
    let errorDetails = {
      message: error.message,
      code: error.code,
      errno: error.errno
    };
    
    if (error.message.includes('PROTOCOL_CONNECTION_LOST')) {
      errorMsg = 'Database connection lost - will retry';
      statusCode = 503;
    } else if (error.message.includes('ER_ACCESS_DENIED')) {
      errorMsg = 'Database authentication failed';
      statusCode = 401;
    } else if (error.message.includes('ER_NO_SUCH_TABLE')) {
      errorMsg = 'Database table not found - initializing';
      statusCode = 503;
    } else if (error.message.includes('ECONNREFUSED') || error.message.includes('connect')) {
      errorMsg = 'Cannot connect to database server';
      statusCode = 503;
      errorDetails.suggestion = 'Check DB_HOST and network connectivity';
    } else if (error.message.includes('PROTOCOL_SEQUENCE_TIMEOUT')) {
      errorMsg = 'Database query timeout';
      statusCode = 504;
    }
    
    res.status(statusCode).json({ 
      error: errorMsg, 
      details: error.message,
      errorCode: error.code,
      fullDetails: process.env.NODE_ENV === 'development' ? errorDetails : undefined
    });
  }
});

// Get cached threat analysis for a specific Gmail email ID

// Get threats for a user
app.get('/api/threats', async (req, res) => {
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.query.userEmail;

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail query parameter' });
  }

  const { limit = 50, offset = 0 } = req.query;

  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const connection = await pool.getConnection();
    
    const limitNum = Math.max(1, Math.min(parseInt(limit) || 50, 1000)); // Clamp between 1-1000
    const offsetNum = Math.max(0, parseInt(offset) || 0);
    
    // LIMIT and OFFSET must be literals in MySQL prepared statements, not parameter placeholders
    // Sort to prioritize: threats first, then spam (low-score safe emails), then other safe, then unscanned by recency
    const query = `
      SELECT id, user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at
      FROM EmailThreats
      WHERE user_email = ?
      ORDER BY 
        CASE threat_level
          WHEN 'danger' THEN 1
          WHEN 'suspicious' THEN 2
          WHEN 'safe' THEN CASE WHEN threat_score < 30 THEN 3 ELSE 4 END
          ELSE 5
        END ASC,
        created_at DESC
      LIMIT ${limitNum} OFFSET ${offsetNum}
    `;
    
    console.log('Executing query for user:', userEmail, 'limit:', limitNum, 'offset:', offsetNum);
    const [rows] = await connection.execute(query, [userEmail]);
    console.log('Query returned', rows.length, 'rows');
    if (rows.length > 0) {
      console.log('First row sample:', JSON.stringify(rows[0], null, 2));
    }

    connection.release();

    // Parse JSON fields
    const threats = rows.map((row) => {
      try {
        // Handle both string and already-parsed objects from database
        const analysisDetails = row.analysis_details 
          ? (typeof row.analysis_details === 'string' ? JSON.parse(row.analysis_details) : row.analysis_details)
          : {};
        // Classify as spam: ONLY if AI explicitly flagged it via analysis_details.isSpam
        // Do NOT use heuristics - be precise
        const isSpam = analysisDetails.isSpam === true;
        
        return {
          ...row,
          isSpam,
          reasons: row.reasons 
            ? (typeof row.reasons === 'string' ? JSON.parse(row.reasons) : row.reasons)
            : [],
          analysis_details: analysisDetails
        };
      } catch (parseError) {
        console.error('JSON parse error for row:', row.id, parseError.message);
        return {
          ...row,
          isSpam: false,
          reasons: [],
          analysis_details: {}
        };
      }
    });

    res.json({ threats, count: threats.length });
  } catch (error) {
    console.error('Error fetching threats:', error.message);
    console.error('Error code:', error.code);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      error: 'Failed to fetch threats', 
      details: error.message,
      code: error.code
    });
  }
});

// Get threat by ID or gmail_email_id
app.get('/api/threats/:identifier', async (req, res) => {
  const { identifier } = req.params;
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.query.userEmail;

  if (!identifier) {
    return res.status(400).json({ error: 'ID or gmail_email_id required' });
  }

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail query parameter' });
  }

  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const connection = await pool.getConnection();
    let query;
    let params;

    // Check if identifier is numeric (database ID) or a Gmail ID string
    if (/^\d+$/.test(identifier)) {
      // Numeric ID - search by database ID
      query = `
        SELECT id, user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at
        FROM EmailThreats
        WHERE id = ? AND user_email = ?
      `;
      params = [identifier, userEmail];
    } else {
      // Gmail email ID - search by gmail_email_id
      query = `
        SELECT id, user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at
        FROM EmailThreats
        WHERE gmail_email_id = ? AND user_email = ?
        ORDER BY created_at DESC
        LIMIT 1
      `;
      params = [identifier, userEmail];
    }

    const [rows] = await connection.execute(query, params);
    connection.release();

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Threat not found' });
    }

    const threat = {
      ...rows[0],
      reasons: typeof rows[0].reasons === 'string' ? JSON.parse(rows[0].reasons) : (rows[0].reasons || []),
      analysis_details: typeof rows[0].analysis_details === 'string' ? JSON.parse(rows[0].analysis_details) : (rows[0].analysis_details || {})
    };

    res.json(threat);
  } catch (error) {
    console.error('Error fetching threat:', error);
    res.status(500).json({ error: 'Failed to fetch threat' });
  }
});

// Delete threat
app.delete('/api/threats/:id', async (req, res) => {
  const { id } = req.params;
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.body?.userEmail;

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail in body' });
  }

  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const connection = await pool.getConnection();
    
    const query = 'DELETE FROM EmailThreats WHERE id = ? AND user_email = ?';
    const [result] = await connection.execute(query, [id, userEmail]);
    
    connection.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Threat not found or unauthorized' });
    }

    res.json({ message: 'Threat deleted successfully' });
  } catch (error) {
    console.error('Error deleting threat:', error);
    res.status(500).json({ error: 'Failed to delete threat' });
  }
});

// General email analysis endpoint - called by frontend
app.post('/api/analyze', async (req, res) => {
  const { sender, subject, content, links } = req.body;

  if (!sender || !subject || !content) {
    return res.status(400).json({ error: 'Missing required fields: sender, subject, content' });
  }

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Gemini API key not configured' });
    }

    // Build analysis prompt
    const prompt = `You are a cybersecurity expert specializing in phishing and spam detection. Analyze the following email and determine if it's a phishing attempt OR spam/marketing email.

Email Details:
- Sender: ${sender}
- Subject: ${subject}
- Content: ${content.substring(0, 8000)}
- Links (${(links || []).length} total): ${(links || []).slice(0, 20).join(', ')}

Analyze for PHISHING:
1. Suspicious sender addresses (spoofing, typos, unusual domains)
2. Urgent or threatening language
3. Requests for personal information
4. Suspicious links (mismatched domains, URL shorteners, typosquatting)
5. Grammar and spelling errors
6. Generic greetings
7. Unusual attachments or requests

Analyze for SPAM/MARKETING - Mark isSpam=true MORE AGGRESSIVELY:
STRONG SPAM INDICATORS (mark isSpam=true if ANY of these apply):
1. Email from known bulk mailer services: Robly, Mailchimp, Klaviyo, Constant Contact, SendGrid, ActiveCampaign, Brevo, GetResponse, ConvertKit, etc.
2. MISSING unsubscribe link/mechanism - MAJOR red flag for unsolicited marketing
3. Sender spoofing generic news/brand names (e.g., "news@robly.com", "alert@marketing-service.com")
4. Multiple recipient indicators (BCC patterns, "Dear Subscriber", "Dear Customer")
5. Obvious mass mailing: repeated templates, batch characteristics, low personalization
6. Deceptive domain masquerading (crime-news domain actually hosted on mail service)
7. Misleading subject lines with urgency/clickbait (fake news angle, false urgency)
8. Suspicious marketing: crypto, get-rich-quick, fake jobs, MLM, pharmacy
9. No legitimate business identifier or clear sender authorization

LEGITIMATE NEWSLETTER EXCEPTION (mark isSpam=false):
- Official domains from known publications (CNN, BBC, Reuters, etc.)
- Legitimate company newsletters with proper branding and verification
- Subscription services user explicitly requested
- Clear unsubscribe present + proper sender identification

CRITICAL: Respond ONLY with valid JSON. No text before or after. No markdown. Just pure JSON.

Required JSON format:
{
  "riskLevel": "SAFE",
  "confidence": 85,
  "isSpam": false,
  "indicators": ["indicator1", "indicator2"],
  "recommendation": "recommendation text",
  "explanation": "explanation text"
}

riskLevel must be exactly: SAFE, SUSPICIOUS, or DANGER (classification for phishing/threats)
confidence must be a number 0-100 (confidence in riskLevel assessment)
isSpam must be true or false (true for deceptive/unsolicited marketing, false for legitimate newsletters)
indicators must be an array of at most 5 SHORT strings, each under 8 words
recommendation must be a single short sentence (max 20 words)
explanation must be a single short sentence (max 20 words)`;

    // Call Gemini API with standard analysis config
    const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' + apiKey, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 1024,
          responseMimeType: 'application/json'
        }
      })
    });

    if (!response.ok) {
      const error = await response.json();
      console.error('Gemini API error:', error);
      return res.status(500).json({ error: 'Gemini API failed: ' + (error.error?.message || response.status) });
    }

    // Parse Gemini response
    const data = await response.json();
    let analysisText = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    
    // Clean up JSON if needed
    analysisText = analysisText.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
    const analysis = JSON.parse(jsonMatch ? jsonMatch[0] : analysisText);

    // Validate response
    if (!analysis.riskLevel || analysis.confidence === undefined) {
      return res.status(500).json({ error: 'Invalid Gemini response format' });
    }

    // Ensure isSpam is set
    if (analysis.isSpam === undefined) {
      analysis.isSpam = false;
    }

    console.log('✅ Email analysis completed:', { riskLevel: analysis.riskLevel, isSpam: analysis.isSpam, confidence: analysis.confidence });
    res.json(analysis);
  } catch (error) {
    console.error('Email analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze email: ' + error.message });
  }
});

// Aggressive reanalysis endpoint
app.post('/api/reanalyze', async (req, res) => {
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.body?.userEmail;
  const { gmailEmailId, sender, subject, content, mode } = req.body;

  if (!userEmail || !gmailEmailId || !mode) {
    return res.status(400).json({ error: 'Missing required fields: userEmail, gmailEmailId, mode' });
  }

  if (!pool) {
    return res.status(503).json({ error: 'Database not available' });
  }

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Gemini API key not configured' });
    }



    // Helper to build prompt with variable content length
    function buildPrompt(contentLen) {
      const safeContent = content ? content.substring(0, contentLen) : '';
      if (mode === 'spam') {
        return `AGGRESSIVE SPAM DETECTION: You are an EMAIL SPAM CLASSIFIER with ZERO TOLERANCE for marketing.

Email Details:
From: ${sender}
Subject: ${subject}
Content: ${safeContent}

MARK AS SPAM (isSpam=true) IF ANY of these apply:
1. Any connection to bulk mailer services (Robly, Mailchimp, SendGrid, Klaviyo, etc.)
2. Missing OR hidden unsubscribe link
3. Generic/"noreply"/"no-reply" sender addresses
4. Mass mailing characteristics or batch send patterns
5. Any marketing-oriented language
6. Link redirects to unknown/suspicious domains
7. Suspicious domain patterns or sender spoofing
8. News/alert masquerading (fake news sources)
9. Generic greetings ("Dear Subscriber", "Dear Customer")
10. When in doubt about legitimacy, mark as spam

Respond ONLY with valid JSON:
{ "isSpam": true, "confidence": 95, "reason": "reason text" }
or
{ "isSpam": false, "confidence": 85, "reason": "reason text" }`;
      } else if (mode === 'phishing') {
        return `AGGRESSIVE PHISHING/SCAM DETECTION: You are a PHISHING/SCAM CLASSIFIER with ZERO TOLERANCE for suspicious activity.

Email Details:
From: ${sender}
Subject: ${subject}
Content: ${safeContent}

MARK AS DANGEROUS (isDanger=true) IF ANY of these apply:
1. Urgent/threatening language demanding immediate action
2. Suspicious sender or domain typosquatting attempts
3. Links that don't match the stated sender domain
4. Requests for credentials, passwords, or authentication
5. Requests for payment, bank details, or financial information
6. Impersonation of known services/companies/brands
7. Spoofed headers or suspicious routing
8. Obfuscated or shortened URLs hiding destination
9. Financial/account threat language ("verify account", "confirm identity")
10. Suspicious attachments or unusual requests
11. When in doubt about legitimacy, mark as dangerous

Respond ONLY with valid JSON:
{ "isDanger": true, "confidence": 95, "reason": "reason text" }
or
{ "isDanger": false, "confidence": 85, "reason": "reason text" }`;
      } else {
        return null;
      }
    }

    // Try with default content length, then retry with smaller if MAX_TOKENS
    let contentLens = [600, 200, 80];
    let lastData = null;
    let lastRawText = null;
    let lastResponse = null;
    let analysisText = null;
    let finishReason = null;
    
    // Phishing prompt is longer, needs more output tokens
    const maxTokens = mode === 'phishing' ? 2048 : 1024;
    
    for (let i = 0; i < contentLens.length; i++) {
      const aggressivePrompt = buildPrompt(contentLens[i]);
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: aggressivePrompt }] }],
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: maxTokens,
            responseMimeType: "application/json"
          }
        })
      });
      lastResponse = response;
      lastRawText = await response.text();
      let data;
      try {
        data = JSON.parse(lastRawText);
      } catch (e) {
        console.error('Gemini API raw response:', lastRawText);
        throw new Error(`Failed to parse Gemini API response: ${e.message}`);
      }
      lastData = data;
      if (!response.ok) {
        const error = data.error || data;
        console.error('Gemini API error response:', data);
        throw new Error(`Gemini API error: ${error.message || error.error?.message || response.status}`);
      }
      // Check structure
      if (!data.candidates || !data.candidates[0] || !data.candidates[0].content || !data.candidates[0].content.parts || !data.candidates[0].content.parts[0]) {
        console.error('Unexpected Gemini API response structure:', JSON.stringify(data));
        return res.status(502).json({
          error: 'Gemini API returned unexpected response structure',
          details: data
        });
      }
      analysisText = data.candidates[0].content.parts[0].text;
      finishReason = data.candidates[0].finishReason;
      // If analysisText is valid and finishReason is not MAX_TOKENS, break
      if (analysisText && analysisText.trim() !== '' && analysisText.trim() !== '{' && analysisText.trim().endsWith('}') && finishReason !== 'MAX_TOKENS') {
        break;
      }
      // If last attempt, break anyway
      if (i === contentLens.length - 1) {
        break;
      }
    }

    if (!analysisText || analysisText.trim() === '' || analysisText.trim() === '{' || !analysisText.trim().endsWith('}')) {
      console.error('Gemini API analysisText is empty or incomplete after retries. Full Gemini response:', JSON.stringify(lastData));
      return res.status(500).json({
        error: 'Gemini API returned empty or incomplete analysis text after retries',
        details: lastData
      });
    }

    let analysis;
    try {
      analysis = JSON.parse(analysisText);
    } catch (e) {
      console.error('Gemini API analysisText not valid JSON:', analysisText);
      console.error('Full Gemini response:', JSON.stringify(data));
      return res.status(502).json({
        error: 'Gemini API analysisText not valid JSON',
        analysisText,
        details: data
      });
    }

    // Determine new threat level based on aggressive analysis
    let newThreatLevel = 'safe';
    let newThreatScore = 10;
    let analysisDetails = { isSpam: false };

    if (mode === 'spam') {
      // If aggressive spam detection flags it, mark as spam
      analysisDetails.isSpam = analysis.isSpam === true;
      if (analysis.isSpam) {
        newThreatLevel = 'safe'; // Spam is categorized separately
        newThreatScore = 25; // Moderate score for spam
      }
    } else if (mode === 'phishing') {
      // If aggressive phishing detection flags it, mark as danger
      if (analysis.isDanger === true) {
        newThreatLevel = 'danger';
        newThreatScore = 95;
      }
    }

    // Update database with reanalysis results
    const connection = await pool.getConnection();
    
    try {
      // Find existing record by gmail_email_id
      const [existingRows] = await connection.execute(
        'SELECT id FROM EmailThreats WHERE gmail_email_id = ? AND user_email = ?',
        [gmailEmailId, userEmail]
      );

      if (existingRows.length > 0) {
        // Update existing record
        const existingId = existingRows[0].id;
        const analysisDetailsJson = JSON.stringify(analysisDetails);
        const reasonsJson = JSON.stringify([analysis.reason]);

        await connection.execute(
          `UPDATE EmailThreats 
           SET threat_level = ?, threat_score = ?, analysis_details = ?, reasons = ?, scanned_at = NOW()
           WHERE id = ? AND user_email = ?`,
          [newThreatLevel, newThreatScore, analysisDetailsJson, reasonsJson, existingId, userEmail]
        );

        console.log(`✅ Reanalysis saved for email ${gmailEmailId}: ${mode} mode`);
      } else {
        console.warn(`⚠️  Email record not found in database for ${gmailEmailId}, creating new record`);
        
        // Insert new record if not found
        const analysisDetailsJson = JSON.stringify(analysisDetails);
        const reasonsJson = JSON.stringify([analysis.reason]);
        
        await connection.execute(
          `INSERT INTO EmailThreats (user_email, gmail_email_id, from_address, subject, threat_level, threat_score, analysis_details, reasons, scanned_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
          [userEmail, gmailEmailId, sender, subject, newThreatLevel, newThreatScore, analysisDetailsJson, reasonsJson]
        );
      }
    } finally {
      connection.release();
    }

    res.json({
      success: true,
      mode,
      reanalysisResult: {
        isSpam: analysis.isSpam,
        isDanger: analysis.isDanger,
        confidence: analysis.confidence,
        reason: analysis.reason
      },
      newThreatLevel,
      newThreatScore,
      message: 'Reanalysis completed and database updated'
    });
  } catch (error) {
    console.error('Reanalysis error:', error);
    res.status(500).json({ error: `Reanalysis failed: ${error.message}` });
  }
});

// Start server with database initialization (with fallback)
const PORT = process.env.PORT || 3000;

function startServer() {
  console.log('🔧 Starting BaitBlocker API...');
  console.log(`📍 Listening on port: ${PORT}`);
  
  // Start server immediately and synchronously
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ BaitBlocker API listening on port ${PORT}`);
    console.log(`🚀 Ready to accept requests`);
  });
  
  // Initialize database in the background (non-blocking)
  console.log('📦 Initializing database connection pool in background...');
  initializeDatabase()
    .then(() => {
      console.log('✅ Database pool ready for requests');
    })
    .catch((error) => {
      console.error('⚠️  Database initialization failed:', error.message);
      console.log('🔄 Will attempt to connect on first request...');
    });
  
  // Graceful shutdown handler
  process.on('SIGTERM', async () => {
    console.log('SIGTERM received - shutting down gracefully...');
    server.close(async () => {
      if (pool) {
        try {
          await pool.end();
          console.log('✅ Database pool closed');
        } catch (error) {
          console.error('Error closing pool:', error.message);
        }
      }
      process.exit(0);
    });
  });
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught exception:', error);
    process.exit(1);
  });
}

// Retry logic for database initialization
async function ensureDatabaseReady() {
  if (pool) return pool;
  
  console.log('🔄 Attempting to initialize database on-demand...');
  try {
    await initializeDatabase();
    console.log('✅ Database initialized on demand');
    return pool;
  } catch (error) {
    console.error('❌ Database still not ready:', error.message);
    throw error;
  }
}

// Start the server
startServer();
