/**
 * Out-of-band PayNym / Monero payment destinations for the billing panel.
 * Display-only; credits are applied manually by the operator after verifying
 * an on-chain payment. Fetches GET /api/oob-payments.
 */

export interface OobPaymentsInfo {
  configured: boolean;
  paynym?: string;
  paynym_payment_code?: string;
  monero_address?: string;
  admin_contact?: string;
}

/** Fetch OOB payment destinations. Returns null when none are configured or on error. */
export async function fetchOobPayments(): Promise<OobPaymentsInfo | null> {
  try {
    const response = await fetch('/api/oob-payments');
    if (!response.ok) return null;
    const data = (await response.json()) as OobPaymentsInfo;
    if (!data.configured) return null;
    return data;
  } catch (err) {
    console.warn('Failed to load out-of-band payment options:', err);
    return null;
  }
}

/**
 * Build a billing-panel section describing manual PayNym and/or Monero top-ups.
 * Returns null when nothing is configured.
 */
export function renderOobPaymentsSection(info: OobPaymentsInfo): HTMLElement | null {
  if (!info.configured) return null;

  const hasPayNym = !!(info.paynym || info.paynym_payment_code);
  const hasMonero = !!info.monero_address;
  if (!hasPayNym && !hasMonero) return null;

  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';

  const h = document.createElement('h4');
  h.textContent = 'Manual Crypto Top-Up';
  wrap.appendChild(h);

  const intro = document.createElement('p');
  intro.className = 'billing-oob-note';
  intro.textContent =
    'These are optional out-of-band payment methods. After you pay, contact the instance admin with your Arkfile username and the transaction ID. Credit is applied manually and is not instant.';
  wrap.appendChild(intro);

  if (hasPayNym) {
    wrap.appendChild(renderPayNymBlock(info));
  }
  if (hasMonero) {
    wrap.appendChild(renderMoneroBlock(info));
  }

  if (info.admin_contact) {
    const contact = document.createElement('p');
    contact.className = 'billing-oob-note';
    contact.textContent = `Admin contact: ${info.admin_contact}`;
    wrap.appendChild(contact);
  }

  return wrap;
}

function renderPayNymBlock(info: OobPaymentsInfo): HTMLElement {
  const block = document.createElement('div');
  block.className = 'billing-oob-method';

  const title = document.createElement('p');
  title.className = 'billing-oob-method-title';
  title.textContent = 'Bitcoin PayNym (BIP47)';
  block.appendChild(title);

  if (info.paynym) {
    const row = document.createElement('p');
    row.className = 'billing-oob-value';
    row.textContent = info.paynym;
    block.appendChild(row);
  }
  if (info.paynym_payment_code) {
    const label = document.createElement('p');
    label.className = 'billing-oob-note';
    label.textContent = 'Payment code';
    block.appendChild(label);
    const code = document.createElement('p');
    code.className = 'billing-oob-value billing-oob-mono';
    code.textContent = info.paynym_payment_code;
    block.appendChild(code);
  }

  const steps = document.createElement('p');
  steps.className = 'billing-oob-note';
  steps.textContent =
    'In Sparrow, Ashigaru, or another BIP47 wallet: open a payment channel to this PayNym (notification transaction), send your top-up amount, wait for confirmations, then message the admin with your username and payment txid.';
  block.appendChild(steps);

  return block;
}

function renderMoneroBlock(info: OobPaymentsInfo): HTMLElement {
  const block = document.createElement('div');
  block.className = 'billing-oob-method';

  const title = document.createElement('p');
  title.className = 'billing-oob-method-title';
  title.textContent = 'Monero (XMR)';
  block.appendChild(title);

  const addr = document.createElement('p');
  addr.className = 'billing-oob-value billing-oob-mono';
  addr.textContent = info.monero_address || '';
  block.appendChild(addr);

  const steps = document.createElement('p');
  steps.className = 'billing-oob-note';
  steps.textContent =
    'Send XMR to this address, wait for confirmations, then message the admin with your Arkfile username and the transaction ID.';
  block.appendChild(steps);

  return block;
}
