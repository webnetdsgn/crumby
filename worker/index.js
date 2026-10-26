// Точка входа Cloudflare Worker: тонкая оболочка над core.js (там вся логика и тесты).
import { DurableObject } from 'cloudflare:workers';
import { HubCore, SqlStore, handleFetch, handleScheduled } from './core.js';

// Одно небольшое хранилище на всё приложение: лимиты запросов, данные людей, подписки на уведомления.
export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.core = new HubCore(new SqlStore(ctx.storage.sql), env);
  }
  async fetch(request) {
    return this.core.fetch(request);
  }
}

export default {
  fetch: (req, env) => handleFetch(req, env),
  scheduled: (event, env, ctx) => {
    ctx.waitUntil(handleScheduled(env));
  },
};
