-- Initialize WAF database
-- This file ensures the database and user are properly set up

-- Create the database if it doesn't exist (this is handled by POSTGRES_DB env var)
-- But we can add any additional setup here

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE waf TO waf;

-- Create extensions if needed
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
