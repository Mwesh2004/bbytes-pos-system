// Test syntax
try {
  require('./backend/server.js')
  console.log('Server syntax OK')
} catch(e) {
  console.log('Error:', e.message)
}
