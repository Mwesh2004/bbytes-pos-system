m// ── BERYLBYTES POS DATABASE SCHEMA & INDEXES ─────────────────────────────
//
// This file defines the data models and indexes for the POS system
// Used for database operations and query optimization

// ── SCHEMA DEFINITIONS ─────────────────────────────────────────────────

const schemas = {
  // User Schema
  users: {
    collection: 'users',
    indexes: [
      { field: 'username', unique: true },
      { field: 'email', unique: true },
      { field: 'role' },
      { field: 'createdAt' },
    ],
    validation: {
      required: ['username', 'password', 'role', 'name'],
      username: { minLength: 3, maxLength: 20, pattern: /^[a-zA-Z0-9_]+$/ },
      password: { minLength: 6 },
      role: { enum: ['superadmin', 'manager', 'cashier', 'inventory', 'accountant', 'audit', 'support'] },
    },
  },

  // Product Schema
  products: {
    collection: 'products',
    indexes: [
      { field: 'category' },
      { field: 'name' },
      { field: 'price' },
      { field: 'id' },
      { field: 'tag' },
    ],
    validation: {
      required: ['id', 'name', 'price', 'category'],
      price: { min: 0, type: 'number' },
      category: { type: 'string' },
    },
  },

  // Transaction Schema
  transactions: {
    collection: 'transactions',
    indexes: [
      { field: 'date' },
      { field: 'timestamp' },
      { field: 'customer' },
      { field: 'method' },
      { field: 'status' },
      { field: 'total' },
      { field: 'id' },
    ],
    validation: {
      required: ['id', 'date', 'timestamp', 'total', 'method', 'status', 'items'],
      id: { pattern: /^INV-\d+$/ },
      total: { min: 0, type: 'number' },
      method: { enum: ['Cash', 'M-Pesa', 'Paystack', 'PayPal'] },
      status: { enum: ['Paid', 'Pending', 'Failed', 'Refunded', 'Reviewed'] },
    },
  },

  // Customer Schema
  customers: {
    collection: 'customers',
    indexes: [
      { field: 'name' },
      { field: 'email' },
      { field: 'phone' },
      { field: 'points' },
      { field: 'totalSpent' },
    ],
    validation: {
      required: ['name'],
      email: { type: 'email' },
      phone: { type: 'string' },
      points: { min: 0, type: 'number' },
    },
  },

  // Inventory Schema
  inventory: {
    collection: 'inventory',
    indexes: [
      { field: 'sku', unique: true },
      { field: 'name' },
      { field: 'category' },
      { field: 'stockLevel' },
      { field: 'expiry' },
      { field: 'batch' },
    ],
    validation: {
      required: ['name', 'sku', 'category'],
      sku: { unique: true },
      stockLevel: { min: 0, type: 'number' },
      minAlert: { min: 0, type: 'number' },
    },
  },

  // Expense Schema
  expenses: {
    collection: 'expenses',
    indexes: [
      { field: 'date' },
      { field: 'category' },
      { field: 'amount' },
    ],
    validation: {
      required: ['desc', 'amount', 'date', 'category'],
      amount: { min: 0, type: 'number' },
      category: { enum: ['Inventory', 'Rent', 'Staff', 'Utilities', 'Marketing', 'Maintenance', 'Other'] },
    },
  },
}

// ── INDEX OPTIMIZATIONS ──────────────────────────────────────────────────────

// Hot indexes (frequently queried)
const hotIndexes = {
  transactions: ['date', 'customer', 'status'],
  products: ['category', 'name'],
  customers: ['phone', 'points'],
  inventory: ['sku', 'stockLevel'],
}

// Cold indexes (infrequently queried)
const coldIndexes = {
  transactions: ['id', 'method'],
  inventory: ['expiry', 'batch'],
}

// ── CATEGORY SCHEMA ─────────────────────────────────────────────────

const categorySchema = {
  shop: { label: 'General Shop', icon: '🛒', products: [] },
  pharmacy: { label: 'Pharmacy', icon: '💊', products: [] },
  airbnb: { label: 'Hospitality', icon: '🏠', products: [] },
  electronics: { label: 'Electronics', icon: '🔌', products: [] },
  salon: { label: 'Salon & Beauty', icon: '💇', products: [] },
  cafe: { label: 'Cafe & Restaurant', icon: '☕', products: [] },
  laundry: { label: 'Laundry', icon: '👕', products: [] },
  hardware: { label: 'Hardware', icon: '🔧', products: [] },
}

// ── ROLE PERMISSIONS ────────────────────────────────────────────────────

const rolePermissions = {
  superadmin: {
    permissions: ['pos', 'dashboard', 'crm', 'inventory', 'add_item', 'settings', 'users', 'reports', 'business_overview', 'expenses', 'ledger', 'companies', 'system_health'],
    canEdit: true,
    canDelete: true,
  },
  manager: {
    permissions: ['pos', 'dashboard', 'crm', 'inventory', 'add_item', 'settings', 'reports', 'expenses', 'ledger'],
    canEdit: true,
    canDelete: false,
  },
  cashier: {
    permissions: ['pos', 'settings'],
    canEdit: false,
    canDelete: false,
  },
  inventory: {
    permissions: ['orders', 'add', 'dashboard'],
    canEdit: true,
    canDelete: false,
  },
  accountant: {
    permissions: ['dashboard'],
    canEdit: false,
    canDelete: false,
  },
  audit: {
    permissions: ['dashboard', 'crm', 'orders'],
    canEdit: false,
    canDelete: false,
  },
  support: {
    permissions: ['crm', 'pos'],
    canEdit: false,
    canDelete: false,
  },
}

// ── EXPORTS ─────────────────────────────────────────────────────────

module.exports = {
  schemas,
  hotIndexes,
  coldIndexes,
  categorySchema,
  rolePermissions,
}
