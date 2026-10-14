/**
 * Minimal in-memory stand-in for the Knex query surface the handlers use.
 * Supports: where (equality), whereNull, select, first, insert, update, delete,
 * forUpdate, transaction, fn.now. Enough to exercise handler logic without MySQL.
 */

// MySQL coerces id types in comparisons ('2' matches 2), so compare as strings.
function matches(row, criteria) {
  return Object.entries(criteria).every(([k, v]) => String(row[k]) === String(v));
}

// Column defaults that the real schema provides on insert.
const DEFAULTS = {
  refresh_tokens: { revoked: false, replaced_by_jti: null, revoked_reason: null, revoked_at: null },
  password_reset_tokens: { used_at: null },
};

class Query {
  constructor(db, table) {
    this.db = db;
    this.table = table;
    this.criteria = {};
    this.nulls = [];
    this.single = false;
    this.op = "select";
    this.patch = null;
    this.row = null;
  }
  where(criteria) { Object.assign(this.criteria, criteria); return this; }
  whereNull(col) { this.nulls.push(col); return this; }
  select() { return this; }
  forUpdate() { return this; }
  first() { this.single = true; return this; }
  insert(row) { this.op = "insert"; this.row = row; return this; }
  update(patch) { this.op = "update"; this.patch = patch; return this; }
  delete() { this.op = "delete"; return this; }

  rows() {
    const list = this.db.tables[this.table];
    return list.filter((r) => matches(r, this.criteria) && this.nulls.every((c) => r[c] == null));
  }

  then(resolve, reject) {
    return this.exec().then(resolve, reject);
  }

  async exec() {
    const list = this.db.tables[this.table];
    if (this.op === "insert") {
      const id = this.db.nextId(this.table);
      list.push({ id, ...(DEFAULTS[this.table] || {}), ...this.row });
      return [id];
    }
    if (this.op === "update") {
      const targets = this.rows();
      targets.forEach((r) => Object.assign(r, this.patch));
      return targets.length;
    }
    if (this.op === "delete") {
      const targets = new Set(this.rows());
      this.db.tables[this.table] = list.filter((r) => !targets.has(r));
      return targets.size;
    }
    const result = this.rows().map((r) => ({ ...r }));
    return this.single ? result[0] : result;
  }
}

export function createFakeDb(seed = {}) {
  const counters = {};
  const db = (table) => new Query(db, table);
  db.tables = {
    users: [],
    refresh_tokens: [],
    password_reset_tokens: [],
    ...structuredClone(seed),
  };
  // Auto-increment starts after the highest seeded id, as a real table would.
  db.nextId = (table) => {
    const seeded = db.tables[table].reduce((max, r) => Math.max(max, Number(r.id) || 0), 0);
    counters[table] = Math.max(counters[table] || 0, seeded) + 1;
    return counters[table];
  };
  db.fn = { now: () => new Date() };
  // Transactions run inline. Writes are not rolled back, which is fine for these specs.
  db.transaction = async (fn) => fn(db);
  return db;
}
