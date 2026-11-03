import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export function createStore() {
  const accounts = new Map();
  const orders = [];
  const partners = new Map();
  const coupons = new Map([
    ['WELCOME10', { percentOff: 10, active: true }],
    ['SPRING25', { percentOff: 25, active: false }],
  ]);
  let nextAccountId = 1;
  let nextOrderId = 1000;

  return {
    addAccount({ name, email, password }) {
      const key = email.toLowerCase();
      if (accounts.has(key)) return null;
      const salt = randomBytes(16);
      const account = {
        id: nextAccountId++,
        name,
        email: key,
        salt,
        hash: scryptSync(password, salt, 32),
      };
      accounts.set(key, account);
      return publicAccount(account);
    },

    verifyLogin(email, password) {
      const account = accounts.get(String(email).toLowerCase());
      if (!account) return null;
      const candidate = scryptSync(String(password), account.salt, 32);
      return timingSafeEqual(candidate, account.hash) ? publicAccount(account) : null;
    },

    addOrder({ email, items }) {
      const total = items.reduce((sum, item) => sum + item.quantity * item.priceCents, 0);
      const order = { id: nextOrderId++, email: email.toLowerCase(), items, totalCents: total };
      orders.push(order);
      return order;
    },

    ordersFor(email) {
      return orders.filter((order) => order.email === String(email).toLowerCase());
    },

    allOrders() {
      return [...orders];
    },

    addPartner(name, key) {
      partners.set(key, { name });
    },

    partnerFor(key) {
      return partners.get(key) ?? null;
    },

    coupon(code) {
      return coupons.get(code) ?? null;
    },
  };
}

function publicAccount({ id, name, email }) {
  return { id, name, email };
}
