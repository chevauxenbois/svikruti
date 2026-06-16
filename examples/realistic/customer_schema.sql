CREATE TABLE customers (
  id UUID PRIMARY KEY,
  full_name TEXT NOT NULL,
  email_address TEXT NOT NULL,
  mobile_number TEXT,
  aadhaar_number TEXT,
  pan_number TEXT,
  address_line TEXT,
  pincode TEXT,
  device_id TEXT,
  created_at TIMESTAMP
);
