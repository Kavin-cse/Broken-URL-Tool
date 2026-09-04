/**
 * @module test-server
 * A local test server that deliberately exposes fake sensitive data
 * to verify the scanner's detection capabilities.
 * 
 * IMPORTANT: This server contains ONLY fake, synthetic data.
 * NEVER PUT REAL SECRETS OR PII IN THIS FILE.
 */

import express from 'express';
import { join } from 'path';

const app = express();
const port = 54321;

// Middlewares
app.use(express.json());
app.use((req, res, next) => {
  // Insecure cookies for testing
  res.cookie('session_id', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature', {
    httpOnly: false, // Insecure
    secure: false, // Insecure
  });
  next();
});

// Serve a basic dashboard that has multiple issues
app.get('/internal/dashboard', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Internal Dashboard</title>
      <meta name="environment" content="staging">
      <!-- TODO security: remove temporary admin auth bypass before prod -->
      <script>
        // Store fake auth token in localStorage
        localStorage.setItem('access_token', 'AKIAIOSFODNN7EXAMPLE'); // Fake AWS-looking key
        localStorage.setItem('user_role', 'administrator');
        
        // Expose a fake API endpoint in JS
        const apiUrl = '/api/employees/v1';
        
        fetch(apiUrl).then(r => r.json()).then(data => {
          console.log('Loaded employees:', data);
          document.getElementById('content').innerText = JSON.stringify(data, null, 2);
        });

        // Some fake PII in JS
        const testUser = {
          email: 'admin@example.local',
          phone: '555-019-8372'
        };
        console.debug('Logged in as', testUser);
      </script>
    </head>
    <body>
      <h1>Internal Dashboard</h1>
      <form action="/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <button type="submit">Login</button>
      </form>
      <div id="content">Loading...</div>
    </body>
    </html>
  `);
});

// Fake API that returns PII and tokens
app.get('/api/employees/v1', (req, res) => {
  res.json({
    status: 'success',
    data: [
      {
        id: 'e-1001',
        name: 'Jane Doe',
        email: 'jane.doe@example.local', // Fake email
        socialSecurityNumber: '000-12-3456', // Fake SSN (000 is invalid)
        salary: 120000,
        role: 'admin'
      },
      {
        id: 'e-1002',
        name: 'John Smith',
        email: 'jsmith@example.local',
        socialSecurityNumber: '000-98-7654', // Fake SSN
        salary: 95000,
        role: 'user'
      }
    ],
    metadata: {
      db_connection: 'mongodb://fakeuser:fakepass123@db.example.local:27017/prod'
    }
  });
});

app.listen(port, () => {
  console.log(`Test server running at http://localhost:${port}`);
  console.log(`Test URL: http://localhost:${port}/internal/dashboard`);
});
