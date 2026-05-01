const bcrypt = require('bcryptjs')

const PINS = {
  PIN_HASH_1: '1234',
  PIN_HASH_2: '2345',
  PIN_HASH_3: '3456',
  PIN_HASH_4: '4567',
  PIN_HASH_5: '5678',
  PIN_HASH_6: '6789',
  PIN_HASH_7: '7890',
  PIN_HASH_8: '8901',
}

async function main() {
  console.log('\n--- Add these to your .env file ---\n')
  for (const [key, pin] of Object.entries(PINS)) {
    const hash = await bcrypt.hash(pin, 12)
    console.log(`${key}=${hash}`)
  }
  console.log('\n--- Never commit .env to git ---\n')
}

main().catch(console.error)