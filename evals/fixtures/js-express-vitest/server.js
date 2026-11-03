import { createApp } from './src/app.js';
import { createStore } from './src/store.js';

const store = createStore();
for (const entry of (process.env.PARTNER_KEYS ?? '').split(',').filter(Boolean)) {
  const [name, key] = entry.split(':');
  store.addPartner(name, key);
}

const port = Number(process.env.PORT ?? 3000);
createApp({ store }).listen(port, () => {
  console.log(`storefront-api listening on :${port}`);
});
