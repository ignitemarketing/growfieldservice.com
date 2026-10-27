interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
  // Worker secrets (set with `wrangler secret put`), kept out of the public repo:
  // where signup notifications go, and the verified Postmark sender they come from.
  NOTIFY_TO: string;
  NOTIFY_FROM: string;
  POSTMARK_SERVER_TOKEN: string;
  // Cloudflare Turnstile secret key. Optional: verification is enforced only when set.
  TURNSTILE_SECRET?: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_FSM = ['Jobber', 'ServiceTitan', 'Housecall Pro', 'Other', ''];
const SITE_ORIGIN = 'https://growfieldservice.com';
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

async function verifyTurnstile(token: unknown, secret: string, ip: string): Promise<boolean> {
  if (typeof token !== 'string' || token === '' || token.length > 2048) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (ip) body.set('remoteip', ip);
  const res = await fetch(TURNSTILE_VERIFY_URL, { method: 'POST', body });
  if (!res.ok) throw new Error(`turnstile siteverify ${res.status}`);
  const out = (await res.json()) as { success?: boolean };
  return out.success === true;
}

async function handleWaitlist(request: Request, env: Env): Promise<Response> {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: {
        'content-type': 'application/json',
        'x-content-type-options': 'nosniff',
      },
    });

  if (!env.NOTIFY_TO || !env.NOTIFY_FROM) {
    console.error('waitlist: NOTIFY_TO / NOTIFY_FROM secrets are not set');
    return json({ ok: false, error: 'server_error' }, 500);
  }

  // Browsers always send Origin on a cross-origin POST; reject any that is not this site.
  const origin = request.headers.get('origin');
  if (origin !== null && origin !== SITE_ORIGIN) {
    return json({ ok: false, error: 'forbidden' }, 403);
  }

  let data: Record<string, unknown>;
  try {
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await request.json();
    } else {
      const form = await request.formData();
      data = Object.fromEntries(form.entries());
    }
  } catch {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  // Honeypot: bots fill this hidden field — silently accept, send nothing.
  if (typeof data.company === 'string' && data.company.trim() !== '') {
    return json({ ok: true });
  }

  const email = String(data.email ?? '').trim().toLowerCase();
  const fsm = String(data.fsm ?? '').trim();
  const source = (String(data.source ?? '').trim() || 'unknown').slice(0, 100);
  const page = String(data.page ?? '').slice(0, 300);

  if (!EMAIL_RE.test(email) || email.length > 254) {
    return json({ ok: false, error: 'invalid_email' }, 422);
  }
  if (!ALLOWED_FSM.includes(fsm)) {
    return json({ ok: false, error: 'invalid_fsm' }, 422);
  }

  if (env.TURNSTILE_SECRET) {
    try {
      const ip = request.headers.get('cf-connecting-ip') || '';
      if (!(await verifyTurnstile(data['cf-turnstile-response'], env.TURNSTILE_SECRET, ip))) {
        return json({ ok: false, error: 'captcha_failed' }, 403);
      }
    } catch {
      return json({ ok: false, error: 'server_error' }, 500);
    }
  }

  const referrer = (request.headers.get('referer') || '').slice(0, 300);
  const ua = (request.headers.get('user-agent') || '').slice(0, 300);
  const country = request.headers.get('cf-ipcountry') || '';

  const textBody = [
    'New waitlist signup',
    '',
    `Source:   ${source}`,
    `Email:    ${email}`,
    `FSM:      ${fsm || '(not provided)'}`,
    `Page:     ${page || '/'}`,
    `Country:  ${country || '(unknown)'}`,
    `Referrer: ${referrer || '(none)'}`,
    `Agent:    ${ua || '(unknown)'}`,
  ].join('\n');

  try {
    const res = await fetch('https://api.postmarkapp.com/email', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-Postmark-Server-Token': env.POSTMARK_SERVER_TOKEN,
      },
      body: JSON.stringify({
        From: env.NOTIFY_FROM,
        To: env.NOTIFY_TO,
        ReplyTo: email,
        Subject: `[newco] Waitlist: ${source} — ${email}`,
        TextBody: textBody,
        MessageStream: 'outbound',
      }),
    });
    if (!res.ok) {
      return json({ ok: false, error: 'server_error' }, 500);
    }
  } catch {
    return json({ ok: false, error: 'server_error' }, 500);
  }

  return json({ ok: true });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/api/waitlist' && request.method === 'POST') {
      return handleWaitlist(request, env);
    }
    return env.ASSETS.fetch(request);
  },
};
