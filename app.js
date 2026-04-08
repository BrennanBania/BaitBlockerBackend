require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();

// ── Error Classification Utility ───────────────────────────────────────────
// Classify errors and add appropriate prefixes for frontend error detection
const classifyError = (error) => {
  const message = error.message || String(error);
  
  // Timeout errors
  if (message.includes('PROTOCOL_SEQUENCE_TIMEOUT') || 
      message.includes('ETIMEDOUT') || 
      message.includes('ECONNRESET') ||
      message.includes('timeout')) {
    return { prefix: 'TIMEOUT', status: 504 };
  }
  
  // Authentication/Session expiration errors
  if (message.includes('ER_ACCESS_DENIED') || 
      message.includes('401') ||
      message.includes('Unauthorized') ||
      message.includes('Invalid token')) {
    return { prefix: 'EXPIRED', status: 401 };
  }
  
  // Connection errors
  if (message.includes('ECONNREFUSED') || 
      message.includes('EHOSTUNREACH') ||
      message.includes('connect') ||
      message.includes('PROTOCOL_CONNECTION_LOST')) {
    return { prefix: 'CONNECTION', status: 503 };
  }
  
  // Database errors
  if (message.includes('ER_NO_SUCH_TABLE') ||
      message.includes('ER_UNKNOWN_COLUMN')) {
    return { prefix: 'DATABASE', status: 500 };
  }
  
  // Default
  return { prefix: 'ERROR', status: 500 };
};

// Format error response with classification prefix
const formatErrorResponse = (error, context = '') => {
  const classification = classifyError(error);
  const message = error.message || String(error);
  
  return {
    error: `${classification.prefix}: ${message}`,
    context: context || undefined,
    code: error.code || error.errno || undefined,
    status: classification.status
  };
};

// Middleware - Configure CORS to allow Chrome extension requests
app.use(cors({
  origin: true, // Allow all origins including chrome-extension://
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// Increase payload size limit to handle large email content
app.use(express.json({ limit: '10mb' }));

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
    const errorResponse = formatErrorResponse(error, 'Database initialization');
    if (errorResponse.error.includes('TIMEOUT')) {
      console.error('🕐 Database connection timeout - check DB_HOST responsiveness');
    } else if (errorResponse.error.includes('EXPIRED')) {
      console.error('🔐 Authentication failed - check DB_USER and DB_PASSWORD');
    } else if (errorResponse.error.includes('CONNECTION')) {
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
    const errorResponse = formatErrorResponse(error, 'Schema check failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context,
      code: errorResponse.code
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
    const errorResponse = formatErrorResponse(error, 'Stats fetch failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context
    });
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
        const errorResponse = formatErrorResponse(initError, 'Emergency database initialization');
        return res.status(errorResponse.status).json({ 
          error: errorResponse.error,
          context: 'Database pool not available during POST /api/threats',
          code: errorResponse.code
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
    
    const classification = classifyError(error);
    const errorResponse = formatErrorResponse(error, 'Error saving threat analysis');
    
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context,
      code: errorResponse.code
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
      SELECT id, user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at, isSeen
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
    const errorResponse = formatErrorResponse(error, 'Threats fetch failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context,
      code: errorResponse.code
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
        SELECT id, user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at, isSeen
        FROM EmailThreats
        WHERE id = ? AND user_email = ?
      `;
      params = [identifier, userEmail];
    } else {
      // Gmail email ID - search by gmail_email_id
      query = `
        SELECT id, user_email, gmail_email_id, from_address, subject, threat_level, threat_score, reasons, analysis_details, scanned_at, created_at, isSeen
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
    const errorResponse = formatErrorResponse(error, 'Threat fetch failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context
    });
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
    const errorResponse = formatErrorResponse(error, 'Threat deletion failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context
    });
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
    const prompt = `You are a cybersecurity expert specializing in email threat detection. Analyze the following email and classify it on TWO INDEPENDENT dimensions:

1. THREAT LEVEL (riskLevel): How dangerous is this email?
   - DANGER: Active phishing, scam, fraud, credential theft, malware
   - SUSPICIOUS: Suspicious characteristics but not confirmed threat
   - SAFE: Legitimate email with no harmful intent

2. SPAM TYPE (isSpam): Is this unsolicited marketing/bulk mail?
   - true: Deceptive marketing, bulk mailer, unsolicited advertisement
   - false: Legitimate business email, transactional, or requested communication

CRITICAL: These are INDEPENDENT classifications. An email can be:
- DANGER + isSpam=true (scam pretending to be legitimate service)
- DANGER + isSpam=false (targeted phishing attack)
- SAFE + isSpam=true (legitimate newsletter you didn't subscribe to)
- SAFE + isSpam=false (legitimate email)

Email Details:
- Sender: ${sender}
- Subject: ${subject}
- Content: ${content.substring(0, 8000)}
- Links (${(links || []).length} total): ${(links || []).slice(0, 20).join(', ')}

THREAT DETECTION (riskLevel):
Mark DANGER if:
1. Phishing/credential theft (fake login pages, urgent action required, account verification)
2. Financial fraud (money transfer requests, banking scams, wire transfer)
3. Impersonation (spoofed sender, fake brand, typosquatting domains)
4. Malware/Attachment threats (suspicious downloads, macro-enabled files)
5. Social engineering/Scams (get-rich-quick, prize claims, romance scams, tech support scams)
6. Business Email Compromise indicators

Mark SUSPICIOUS if:
1. Some phishing characteristics but not definitive
2. Unusual sender + unusual request combination
3. Suspicious links but otherwise legitimate-looking
4. Premium service offers without clear legitimacy

Mark SAFE if:
1. Email from authenticated domain you recognize
2. Clear business purpose with no suspicious elements
3. Legitimate transactional email (receipt, confirmation, alert)
4. No requests for sensitive information or action

SPAM CLASSIFICATION (isSpam):
Mark isSpam=true ONLY for unsolicited bulk marketing:
1. Email from bulk mailer services (Mailchimp, SendGrid, Klaviyo, etc.)
2. Missing unsubscribe or hard to unsubscribe
3. Generic bulk template characteristics
4. Deceptive subject line (fake urgency, clickbait not matching content)

Mark isSpam=false for:
1. Legitimate newsletters you can verify
2. Transactional emails (receipts, confirmations)
3. Business communications (support, alerts)
4. Even if it's risky, if it's targeted/legitimate-looking

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

riskLevel must be exactly: SAFE, SUSPICIOUS, or DANGER
confidence must be 0-100 for riskLevel assessment
isSpam must be true or false for marketing classification
indicators: list up to 5 key findings, max 8 words each
recommendation: single sentence max 20 words for user action
explanation: single sentence max 20 words why this classification`;

    // Call Gemini API with standard analysis config
    const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' + apiKey, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 4096,
          responseMimeType: 'application/json'
        }
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('⚠️ Gemini API error (status ' + response.status + '):', errorText.substring(0, 200));
      // Don't crash - return safe/unscanned instead
      const analysis = {
        riskLevel: 'SAFE',
        confidence: 0,
        isSpam: false,
        indicators: ['API temporarily unavailable'],
        recommendation: 'Could not analyze at this time, treating as safe',
        explanation: 'Analysis service temporarily unavailable'
      };
      return res.json({ 
        reanalysisResult: analysis,
        geminiDecision: 'SAFE_DEFAULT_FALLBACK'
      });
    }

    // Parse Gemini response
    let data;
    try {
      data = await response.json();
    } catch (jsonError) {
      console.error('⚠️ Failed to parse Gemini response as JSON:', jsonError.message);
      // Return safe fallback if response isn't valid JSON
      const analysis = {
        riskLevel: 'SAFE',
        confidence: 0,
        isSpam: false,
        indicators: ['Response parsing failed'],
        recommendation: 'Could not analyze, treating as safe',
        explanation: 'Analysis service returned invalid response'
      };
      return res.json({ 
        reanalysisResult: analysis,
        geminiDecision: 'SAFE_DEFAULT_FALLBACK'
      });
    }
    
    let analysisText = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    
    // Clean up JSON if needed
    analysisText = analysisText.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    
    let analysis;
    try {
      const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
      analysis = JSON.parse(jsonMatch ? jsonMatch[0] : analysisText);
    } catch (parseError) {
      console.error('Failed to parse Gemini response:', analysisText);
      // Fallback to safe response if parsing fails
      analysis = {
        riskLevel: 'SAFE',
        confidence: 50,
        isSpam: false,
        indicators: ['Unable to fully analyze'],
        recommendation: 'Could not fully analyze this email',
        explanation: 'Analysis service encountered difficulty with this email'
      };
    }

    // Validate response
    if (!analysis.riskLevel || analysis.confidence === undefined) {
      analysis.riskLevel = 'SAFE';
      analysis.confidence = 50;
    }

    // Ensure isSpam is set
    if (analysis.isSpam === undefined) {
      analysis.isSpam = false;
    }

    console.log('✅ Email analysis completed:', { riskLevel: analysis.riskLevel, isSpam: analysis.isSpam, confidence: analysis.confidence });
    res.json(analysis);
  } catch (error) {
    console.error('Email analysis error:', error);
    const errorResponse = formatErrorResponse(error, 'Email analysis failed');
    
    // For analysis endpoint, return safe default on error instead of 5xx
    // This prevents the extension from breaking on transient failures
    res.json({
      riskLevel: 'SAFE',
      confidence: 30,
      isSpam: false,
      indicators: [errorResponse.error],
      recommendation: 'Contact support if issues persist',
      explanation: 'Email analysis service encountered an issue'
    });
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
        return `EMAIL SPAM CLASSIFICATION: You are an EMAIL SPAM DETECTOR. Focus on ACTUAL SPAM characteristics, not legitimate marketing.

Email Details:
From: ${sender}
Subject: ${subject}
Content: ${safeContent}

MARK AS SPAM (isSpam=true) ONLY IF MULTIPLE of these apply:
1. Obvious bulk mailer service HEADERS or unsubscribe links pointing to mass mailer platforms (Mailchimp, SendGrid, Klaviyo unsubscribe pages - NOT including legitimate service notifications)
2. COMPLETELY missing unsubscribe link (legitimate services always include one)
3. Generic BATCH SENDER patterns ("noreply@" + unfamiliar domain with multiple recipients - NOT single service notifications)
4. IDENTICAL template structure repeated across multiple emails (only identifiable if pattern provided)
5. SUSPICIOUS URGENCY combined with requests for personal data or payment
6. Clear indicators of mass marketing campaigns with deceptive practices
7. OBVIOUS phishing-style links redirecting to suspicious domains
8. SPOOFED sender address impersonating known companies with mismatched domains
9. Unsolicited bulk advertisements with hidden or fake sender identity

DO NOT mark as spam if:
- Email is from a legitimate service the recipient subscribed to (Rocket Money, PayPal, bank alerts, etc.)
- Email contains standard marketing language but has legitimate unsubscribe link
- Email is a transactional notification (receipt, confirmation, alert)
- Email is from a recognizable company with proper sender authentication
- Email appears to be legitimate service communication

Respond ONLY with valid JSON:
{ "isSpam": true, "confidence": 95, "reason": "reason text" }
or
{ "isSpam": false, "confidence": 85, "reason": "reason text" }`;
      } else if (mode === 'phishing') {
        return `EMAIL PHISHING/SCAM CLASSIFICATION: You are a PHISHING/SCAM DETECTOR specialized in identifying fraudulent emails. Focus on ACTUAL security threats, not legitimate urgent communications.

Email Details:
From: ${sender}
Subject: ${subject}
Content: ${safeContent}

MARK AS DANGEROUS (isDanger=true) ONLY IF MULTIPLE of these apply:
1. Sender domain is SPOOFED or impersonates a known company (e.g., "paypa1.com" instead of "paypal.com") - verify domain authenticity
2. Unsolicited requests for sensitive information: passwords, credit card numbers, authentication codes, SSN, PINs
3. Urgent/threatening language combined with action requests ("Verify account NOW or access will be LOCKED")
4. Links that redirect to DIFFERENT domains than stated in email (e.g., "Update PayPal" linked to "secure-paypa1-verify.xyz")
5. Social engineering tactics using fake urgency, account threats, or prize claims
6. Malicious attachments or suspicious download requests with deceptive names
7. Requests for payment to "unlock" accounts, claim prizes, or resolve problems
8. Multiple phishing indicators (spoofed sender + credential request + urgent language)
9. Known phishing patterns or obfuscated URLs hiding malicious destinations

DO NOT mark as dangerous if:
- Email is from a legitimate service the recipient uses (legitimate password resets, account alerts, etc.)
- Email is a standard security notification with proper sender authentication
- Email contains legitimate urgent language (outages, billing issues) but from verified company domain
- Email is asking users to contact support through official channels (not via suspicious links)
- Email appears to be a legitimate transactional notification or legitimate service communication
- Sender domain can be verified as legitimate through proper DNS/DKIM checks

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
    
    // Both modes need sufficient tokens - aggressive analysis produces longer responses
    const maxTokens = mode === 'phishing' ? 4096 : 4096;
    
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
        console.log(`✅ Complete response received on attempt ${i + 1}`);
        break;
      }
      // If we hit token limit, log and continue to next retry
      if (finishReason === 'MAX_TOKENS') {
        console.log(`⚠️  Token limit hit on attempt ${i + 1}, retrying with shorter content...`);
      }
      // If last attempt, break anyway (even if incomplete)
      if (i === contentLens.length - 1) {
        console.log(`⚠️  Final attempt (${i + 1}/${contentLens.length}) - response: ${analysisText.substring(0, 100)}...`);
        break;
      }
    }

    // More lenient validation - try to work with partial responses
    if (!analysisText || analysisText.trim() === '' || analysisText.trim() === '{') {
      console.error('Gemini API analysisText is completely empty after retries. Full Gemini response:', JSON.stringify(lastData));
      return res.status(500).json({
        error: 'Gemini API returned empty analysis text after retries',
        details: lastData
      });
    }

    let analysis;
    try {
      analysis = JSON.parse(analysisText);
    } catch (e) {
      // If JSON parsing fails, try to extract partial JSON
      console.warn('⚠️  Incomplete JSON detected, attempting to extract:', analysisText.substring(0, 150));
      
      // Try to find and close the JSON object if incomplete
      const closingBrace = analysisText.lastIndexOf('}');
      if (closingBrace > 0) {
        const truncated = analysisText.substring(0, closingBrace + 1);
        try {
          analysis = JSON.parse(truncated);
          console.log('✅ Successfully parsed truncated JSON:', JSON.stringify(analysis));
        } catch (e2) {
          console.error('Failed to parse even truncated JSON:', truncated.substring(0, 150));
          return res.status(502).json({
            error: 'Gemini API returned incomplete/invalid JSON',
            analysisText: analysisText.substring(0, 200),
            details: lastData
          });
        }
      } else {
        console.error('No closing brace found in response. Full response:', analysisText);
        return res.status(502).json({
          error: 'Gemini API response has no closing brace',
          analysisText: analysisText.substring(0, 200),
          details: lastData
        });
      }
    }

    // Validate we got minimum required fields (even if response was incomplete)
    if (!analysis || typeof analysis !== 'object') {
      return res.status(502).json({
        error: 'Gemini API parse result is not an object',
        analysisText: analysisText.substring(0, 200),
        details: lastData
      });
    }
    
    // IMPORTANT: Trust Gemini's analysis completely - user report is just a suggestion to re-check with aggressive rules
    let newThreatLevel = 'safe';
    let newThreatScore = 10;
    let analysisDetails = { isSpam: false };
    let geminiDecision = null;

    if (mode === 'spam') {
      // User suggested this might be SPAM - run aggressive spam detection
      // BUT: Only mark as spam if Gemini's analysis confirms it
      // If Gemini says it's NOT spam, it stays SAFE (trust Gemini)
      analysisDetails.isSpam = analysis.isSpam === true;
      
      if (analysis.isSpam === true) {
        // Require minimum 75% confidence to mark as spam
        if ((analysis.confidence || 0) >= 75) {
          geminiDecision = 'SPAM_CONFIRMED';
          newThreatLevel = 'safe'; 
          newThreatScore = 25;
          console.log(`✅ ${mode} mode: Gemini confirmed SPAM at ${analysis.confidence}% confidence`);
        } else {
          geminiDecision = 'SPAM_LOW_CONFIDENCE_REJECTED';
          newThreatLevel = 'safe';
          newThreatScore = 10;
          console.log(`⚠️  ${mode} mode: Spam detected but confidence too low (${analysis.confidence}%) - keeping as SAFE`);
        }
      } else {
        geminiDecision = 'SPAM_REJECTED_AS_SAFE';
        newThreatLevel = 'safe';
        newThreatScore = 10;
        console.log(`✅ ${mode} mode: Gemini says NOT SPAM - keeping as SAFE (confidence: ${analysis.confidence})`);
      }
    } else if (mode === 'phishing') {
      // User suggested this might be SCAM/PHISHING - run aggressive phishing detection
      // When we find phishing, mark it as NOT spam (it's a genuine threat, not just marketing)
      analysisDetails.isSpam = false;
      
      // Require minimum 75% confidence to mark as danger
      if (analysis.isDanger === true) {
        if ((analysis.confidence || 0) >= 75) {
          geminiDecision = 'PHISHING_CONFIRMED';
          newThreatLevel = 'danger';
          newThreatScore = 95;
          console.log(`⚠️  ${mode} mode: Gemini confirmed PHISHING/SCAM at ${analysis.confidence}% confidence`);
        } else {
          geminiDecision = 'PHISHING_LOW_CONFIDENCE_REJECTED';
          newThreatLevel = 'safe';
          newThreatScore = 10;
          console.log(`⚠️  ${mode} mode: Phishing detected but confidence too low (${analysis.confidence}%) - keeping as SAFE`);
        }
      } else {
        geminiDecision = 'PHISHING_REJECTED_AS_SAFE';
        newThreatLevel = 'safe';
        newThreatScore = 10;
        console.log(`✅ ${mode} mode: Gemini says NOT PHISHING - keeping as SAFE (confidence: ${analysis.confidence})`);
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
      userReported: mode, // What the user suggested to re-check
      geminiDecision, // What Gemini actually found (the source of truth)
      reanalysisResult: {
        geminiSaysSpam: analysis.isSpam,
        geminiSaysDangerous: analysis.isDanger,
        confidence: analysis.confidence,
        reason: analysis.reason
      },
      // Final classification (what we trust)
      newThreatLevel,
      newThreatScore,
      message: `Reanalysis completed. Gemini ${geminiDecision === 'SPAM_CONFIRMED' || geminiDecision === 'PHISHING_CONFIRMED' ? 'confirmed' : 'rejected'} the ${mode} suggestion. Classification updated.`
    });
  } catch (error) {
    console.error('Reanalysis error:', error);
    const errorResponse = formatErrorResponse(error, 'Email reanalysis failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context,
      code: errorResponse.code
    });
  }
});

// Mark email as safe (update threat_level to 'safe')
app.put('/api/threats/:identifier/mark-safe', async (req, res) => {
  const { identifier } = req.params;
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.body?.userEmail;

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail in body' });
  }

  if (!identifier) {
    return res.status(400).json({ error: 'Email ID required' });
  }

  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    const connection = await pool.getConnection();
    
    // identifier can be either database id (numeric) or gmail_email_id (string)
    let query;
    let params;
    
    if (/^\d+$/.test(identifier)) {
      // Numeric - database ID
      query = `
        UPDATE EmailThreats 
        SET threat_level = 'safe', threat_score = 10, analysis_details = ?
        WHERE id = ? AND user_email = ?
      `;
      params = [JSON.stringify({ userMarkedSafe: true }), identifier, userEmail];
    } else {
      // String - Gmail email ID
      query = `
        UPDATE EmailThreats 
        SET threat_level = 'safe', threat_score = 10, analysis_details = ?
        WHERE gmail_email_id = ? AND user_email = ?
      `;
      params = [JSON.stringify({ userMarkedSafe: true }), identifier, userEmail];
    }
    
    const [result] = await connection.execute(query, params);
    
    connection.release();

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Email not found or unauthorized' });
    }

    res.json({ success: true, message: 'Email marked as safe' });
  } catch (error) {
    console.error('Error marking email as safe:', error);
    const errorResponse = formatErrorResponse(error, 'Mark as safe failed');
    res.status(errorResponse.status).json({ 
      error: errorResponse.error,
      context: errorResponse.context,
      code: errorResponse.code
    });
  }
});

// Mark email as reviewed (set isSeen to true)
app.put('/api/threats/:identifier/mark-seen', async (req, res) => {
  const { identifier } = req.params;
  const userEmail = req.userEmail || req.headers['x-user-email'] || req.body?.userEmail;

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required. Send via x-user-email header or userEmail in body' });
  }

  if (!identifier) {
    return res.status(400).json({ error: 'Email ID required' });
  }

  let connection;
  try {
    if (!pool) {
      return res.status(503).json({ error: 'Database not available' });
    }

    connection = await pool.getConnection();
    
    // identifier can be either database id (numeric) or gmail_email_id (string)
    let query;
    let params;
    
    if (/^\d+$/.test(identifier)) {
      // Numeric - database ID
      query = `
        UPDATE EmailThreats 
        SET isSeen = true
        WHERE id = ? AND user_email = ?
      `;
      params = [identifier, userEmail];
    } else {
      // String - Gmail email ID
      query = `
        UPDATE EmailThreats 
        SET isSeen = true
        WHERE gmail_email_id = ? AND user_email = ?
      `;
      params = [identifier, userEmail];
    }
    
    const [result] = await connection.execute(query, params);

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: 'Email not found or unauthorized' });
    }

    connection.release();
    res.json({ success: true, message: 'Email marked as reviewed' });
    
  } catch (error) {
    // Check if error is due to missing column
    const errorMsg = error.message || '';
    const isMissingColumn = errorMsg.includes('UNKNOWN_COLUMN') || 
                           errorMsg.includes('ER_BAD_FIELD_ERROR') || 
                           errorMsg.includes('Unknown column') ||
                           errorMsg.includes('1054');
    
    if (isMissingColumn) {
      console.log('📝 isSeen column not found, creating it...');
      try {
        if (!connection) {
          connection = await pool.getConnection();
        }
        
        // Create the column
        await connection.execute(`
          ALTER TABLE EmailThreats 
          ADD COLUMN isSeen BOOLEAN DEFAULT false
        `);
        console.log('✅ isSeen column created successfully');
        
        // Now update the record
        let updateQuery;
        let updateParams;
        
        if (/^\d+$/.test(identifier)) {
          updateQuery = `
            UPDATE EmailThreats 
            SET isSeen = true
            WHERE id = ? AND user_email = ?
          `;
          updateParams = [identifier, userEmail];
        } else {
          updateQuery = `
            UPDATE EmailThreats 
            SET isSeen = true
            WHERE gmail_email_id = ? AND user_email = ?
          `;
          updateParams = [identifier, userEmail];
        }
        
        const [updateResult] = await connection.execute(updateQuery, updateParams);
        connection.release();

        if (updateResult.affectedRows === 0) {
          return res.status(404).json({ error: 'Email not found or unauthorized' });
        }

        res.json({ success: true, message: 'Email marked as reviewed', columnCreated: true });
      } catch (alterError) {
        if (connection) connection.release();
        console.error('❌ Error creating column:', alterError.message);
        const errorResponse = formatErrorResponse(alterError, 'Failed to create/update isSeen column');
        res.status(errorResponse.status).json({ 
          error: errorResponse.error,
          context: errorResponse.context,
          code: errorResponse.code
        });
      }
    } else {
      if (connection) connection.release();
      console.error('Error marking email as seen:', error.message);
      const errorResponse = formatErrorResponse(error, 'Mark as seen failed');
      res.status(errorResponse.status).json({ 
        error: errorResponse.error,
        context: errorResponse.context,
        code: errorResponse.code
      });
    }
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
