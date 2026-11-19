// GraphQL endpoint, switched on at level 6 only.
import express from 'express';
import {
  buildSchema, parse, validate, execute, specifiedRules, NoSchemaIntrospectionCustomRule, GraphQLError, Kind,
} from 'graphql';
import { db } from './db.js';
import { vuln, award } from './config.js';
import { verifyOtp } from './otp.js';
import { issueAccessToken } from './tokens.js';
import { stats } from './routes/admin.js';

const MAX_DEPTH = 6;
const MAX_ALIASES = 5;

const schema = buildSchema(`
  type Query {
    me: User
    restaurants(limit: Int = 10): [Restaurant!]!
    restaurant(id: ID!): Restaurant
    adminStats: AdminStats
  }
  type Mutation {
    verifyOtp(email: String!, code: String!): OtpResult!
  }
  type User { id: ID!, name: String, email: String, role: String }
  type Restaurant { id: ID!, name: String, cuisine: String, city: String, menu: [MenuItem!]!, reviews: [Review!]! }
  type MenuItem { id: ID!, name: String, price: Float, restaurant: Restaurant }
  type Review { id: ID!, rating: Int, comment: String, restaurant: Restaurant }
  type AdminStats { users: Int, orders: Int, revenue: Float, restaurants: Int }
  type OtpResult { ok: Boolean!, accessToken: String }
`);

const getRest = (rid) => db.prepare('SELECT * FROM restaurants WHERE id = ? AND approved = 1').get(rid);
const restaurant = (r) => r && {
  id: r.id, name: r.name, cuisine: r.cuisine, city: r.city,
  menu: () => db.prepare('SELECT * FROM menu_items WHERE restaurant_id = ? AND available = 1 ORDER BY id LIMIT 50').all(r.id).map(menuItem),
  reviews: () => db.prepare('SELECT * FROM reviews WHERE restaurant_id = ? ORDER BY id DESC LIMIT 50').all(r.id).map(review),
};
const menuItem = (i) => ({ id: i.id, name: i.name, price: i.price, restaurant: () => restaurant(getRest(i.restaurant_id)) });
const review = (v) => ({ id: v.id, rating: v.rating, comment: v.comment, restaurant: () => restaurant(getRest(v.restaurant_id)) });

const root = {
  me: (_a, ctx) => ctx.user && { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email, role: ctx.user.role },
  restaurants: ({ limit }) => {
    const n = Math.max(1, Math.min(limit, listCap()));
    return db.prepare('SELECT * FROM restaurants WHERE approved = 1 ORDER BY id LIMIT ?').all(n).map(restaurant);
  },
  restaurant: ({ id }) => restaurant(getRest(Number(id))),
  adminStats: (_a, ctx) => {
    if (!ctx.user) throw new GraphQLError('Authentication required');
    if (ctx.user.role !== 'admin') {
      if (!vuln('L6-GQL-ADMIN-FIELD')) throw new GraphQLError('Forbidden');
      ctx.flags.add('L6-GQL-ADMIN-FIELD');
    }
    return stats();
  },
  verifyOtp: ({ email, code }, ctx) => {
    const result = verifyOtp(String(email).toLowerCase(), code, ctx.ip);
    for (const id of result.awards) ctx.flags.add(id);
    return result.ok ? { ok: true, accessToken: issueAccessToken(result.user) } : { ok: false, accessToken: null };
  },
};
const listCap = () => (vuln('L6-GQL-DEPTH') ? 200 : 50);

// Depth of a selection set, ignoring introspection fields. Each fragment's depth is worked
// out once and cached, so nested fragment spreads cannot make this walk exponential.
function depth(node, fragments, memo = new Map(), visiting = new Set()) {
  if (!node.selectionSet) return 0;
  let max = 0;
  for (const sel of node.selectionSet.selections) {
    if (sel.kind === Kind.FIELD) {
      if (!sel.name.value.startsWith('__')) max = Math.max(max, 1 + depth(sel, fragments, memo, visiting));
    } else if (sel.kind === Kind.INLINE_FRAGMENT) {
      max = Math.max(max, depth(sel, fragments, memo, visiting));
    } else if (sel.kind === Kind.FRAGMENT_SPREAD) {
      const name = sel.name.value;
      if (!memo.has(name) && fragments[name] && !visiting.has(name)) {
        visiting.add(name);
        memo.set(name, depth(fragments[name], fragments, memo, visiting));
        visiting.delete(name);
      }
      max = Math.max(max, memo.get(name) ?? 0);
    }
  }
  return max;
}

function aliases(doc) {
  const found = [];
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    if (node.kind === Kind.FIELD && node.alias) found.push(node.name.value);
    for (const v of Object.values(node)) {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object' && v.kind) walk(v);
    }
  };
  walk(doc);
  return found;
}

export function graphqlRoutes() {
  const router = express.Router();
  router.post('/graphql', async (req, res) => {
    const { query, variables, operationName } = req.body ?? {};
    if (typeof query !== 'string') return res.status(400).json({ errors: [{ message: 'Send a JSON body with a query string' }] });
    let doc;
    try { doc = parse(query, { maxTokens: 2000 }); } catch (e) { return res.status(400).json({ errors: [{ message: e.message }] }); }

    const fragments = Object.fromEntries(doc.definitions.filter((d) => d.kind === Kind.FRAGMENT_DEFINITION).map((d) => [d.name.value, d]));
    const ops = doc.definitions.filter((d) => d.kind === Kind.OPERATION_DEFINITION);
    const memo = new Map();
    const deepest = Math.max(0, ...ops.map((op) => depth(op, fragments, memo)));
    const aliased = aliases(doc);
    const flags = new Set();

    if (vuln('L6-GQL-DEPTH')) {
      if (deepest > 8) flags.add('L6-GQL-DEPTH');
    } else if (deepest > MAX_DEPTH) {
      return res.status(400).json({ errors: [{ message: `Query is too deep (${deepest}, limit ${MAX_DEPTH})` }] });
    }
    if (vuln('L6-GQL-ALIAS-BATCH')) {
      if (aliased.filter((n) => n === 'verifyOtp').length >= 10) flags.add('L6-GQL-ALIAS-BATCH');
    } else if (aliased.length > MAX_ALIASES) {
      return res.status(400).json({ errors: [{ message: `Too many aliases (${aliased.length}, limit ${MAX_ALIASES})` }] });
    }

    const rules = vuln('L6-GQL-ADMIN-FIELD') ? specifiedRules : [...specifiedRules, NoSchemaIntrospectionCustomRule];
    const errors = validate(schema, doc, rules);
    if (errors.length) return res.status(400).json({ errors: errors.map((e) => ({ message: e.message })) });

    const result = await execute({
      schema, document: doc, rootValue: root, variableValues: variables, operationName,
      contextValue: { user: req.user, flags, ip: req.ip },
    });
    for (const id of flags) award(res, id);
    res.json(result);
  });
  return router;
}
