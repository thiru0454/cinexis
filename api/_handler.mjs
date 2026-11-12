import { dispatchApi } from '../server.mjs';

export default async function handler(request, response) {
  const origin = `https://${request.headers.host || 'localhost'}`;
  const url = new URL(request.url || '/', origin);
  await dispatchApi(request, response, url);
}
