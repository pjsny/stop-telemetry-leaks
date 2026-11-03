'use strict';

const http = require('node:http');
const https = require('node:https');

function createCreditClient({ baseUrl, apiToken, timeoutMs = 2000 }) {
  return {
    score(customerId) {
      const url = new URL('/v1/score', baseUrl);
      url.searchParams.set('customer', String(customerId));
      url.searchParams.set('access_token', apiToken);
      const transport = url.protocol === 'https:' ? https : http;

      return new Promise((resolve, reject) => {
        const req = transport.get(url, { timeout: timeoutMs }, (res) => {
          let raw = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            raw += chunk;
          });
          res.on('end', () => {
            if (res.statusCode !== 200) {
              reject(new Error(`credit service responded ${res.statusCode}`));
              return;
            }
            try {
              resolve(JSON.parse(raw));
            } catch (err) {
              reject(err);
            }
          });
        });
        req.on('timeout', () => req.destroy(new Error('credit service timed out')));
        req.on('error', reject);
      });
    },
  };
}

module.exports = { createCreditClient };
