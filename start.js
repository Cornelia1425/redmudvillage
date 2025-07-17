const express = require('express');
const path = require('path');
const fs = require('fs');

// Simple setup script to serve both frontend and backend
const app = express();

// Serve static files from frontend directory
app.use(express.static(path.join(__dirname, 'frontend')));

// API routes would go here (or proxy to backend server)
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Setup server running' });
});

// Serve the main chat room
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

const PORT = process.env.SETUP_PORT || 8080;

app.listen(PORT, () => {
  console.log(`\n🏘️ RedMudVillage Community Setup Server Running!`);
  console.log(`📱 Frontend: http://localhost:${PORT}`);
  console.log(`🔧 Make sure to start the backend server on port 3000`);
  console.log(`\n📁 File Structure:`);
  console.log(`   redmudvillage/`);
  console.log(`   ├── backend/`);
  console.log(`   │   ├── server.js`);
  console.log(`   │   ├── package.json`);
  console.log(`   │   └── .env`);
  console.log(`   ├── frontend/`);
  console.log(`   │   └── index.html`);
  console.log(`   └── start.js (this file)`);
  console.log(`\n🛠️  Next Steps:`);
  console.log(`   1. Set up PostgreSQL database`);
  console.log(`   2. Configure .env file`);
  console.log(`   3. Run: cd backend && npm install && npm run dev`);
  console.log(`   4. Open browser to http://localhost:${PORT}`);
  console.log(`\n🏘️ Welcome to RedMudVillage - Join our global community!`);
});