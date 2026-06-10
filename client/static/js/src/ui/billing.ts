/**
 * Billing panel UI for storage credits / usage metering.
 *
 * Renders one inline panel (matching the security-settings + contact-info
 * pattern) with three sections:
 *
 *   1. Balance              -- signed four-decimal USD; below-baseline note.
 *   2. Current Storage and  -- storage used / free baseline / billable bytes;
 *      Cost                    when there is billable usage, also projected
 *                              monthly cost and estimated runway.
 *   3. Transaction History  -- only rendered when there is at least one
 *                              transaction (no empty-state heading).
 *
 * Privacy posture: this module makes a single GET to /api/credits and
 * renders the response directly. No analytics, no third-party scripts.
 *
 * CSS hooks (defined in client/static/css/styles.css under the
 * "Billing panel" comment block):
 *   .billing-panel-section, .billing-panel-section h4
 *   .billing-balance-amount[.negative]
 *   .billing-runway, .billing-below-baseline
 *   .billing-usage-grid (dt, dd)
 *   .billing-tx-table, .billing-tx-amount[.negative], .billing-tx-balance[.negative]
 */

import { authenticatedFetch } from '../utils/auth';

/** Toggle the billing panel visibility, loading data on open. */
export async function toggleBillingPanel(): Promise<void> {
  const panel = document.getElementById('billing-panel');
  if (!panel) return;

  const isHidden = panel.classList.contains('hidden');
  panel.classList.toggle('hidden');

  // Mutual exclusion with the other inline panels.
  closeOtherPanels('billing-panel');

  if (isHidden) {
    await loadBilling();
  }
}

/** Close any open sibling panel except `keep`. */
function closeOtherPanels(keep: string): void {
  for (const id of ['security-settings', 'contact-info-panel', 'billing-panel']) {
    if (id === keep) continue;
    const el = document.getElementById(id);
    if (el && !el.classList.contains('hidden')) {
      el.classList.add('hidden');
    }
  }
}

interface CurrentUsage {
  total_storage_bytes: number;
  free_baseline_bytes: number;
  billable_bytes: number;
  rate_microcents_per_gib_per_hour: number;
  rate_human: string;
  current_cost_per_month_microcents: number;
  current_cost_per_month_usd_approx: string;
}

interface CreditsRunway {
  estimated_hours_remaining: number | null;
  estimated_runs_out_at_approx?: string;
  computed_at: string;
  note?: string;
}

interface Transaction {
  id: number;
  amount_usd_microcents: number;
  formatted_amount?: string;
  balance_after_usd_microcents: number;
  formatted_balance_after?: string;
  transaction_type: string;
  reason: string;
  admin_username?: string | null;
  created_at: string;
}

interface PaymentsConfig {
  enabled: boolean;
  min_top_up: string;
  max_top_up: string;
}

interface CreditsResponse {
  username: string;
  balance_usd_microcents: number;
  formatted_balance: string;
  current_usage?: CurrentUsage;
  credits_runway?: CreditsRunway;
  transactions?: Transaction[];
  payments?: PaymentsConfig;
}

/** Fetch /api/credits and render the panel. */
export async function loadBilling(): Promise<void> {
  const content = document.getElementById('billing-panel-content');
  if (!content) return;
  content.innerHTML = '<p>Loading…</p>';

  try {
    const response = await authenticatedFetch('/api/credits', { method: 'GET' });
    if (!response.ok) {
      if (response.status === 401) {
        content.innerHTML = '<p>Session expired. Please log in again.</p>';
        return;
      }
      throw new Error(`Server returned ${response.status}`);
    }
    const result = await response.json();
    const data = (result.data || result) as CreditsResponse;
    renderBilling(content, data);
  } catch (err) {
    console.error('Failed to load billing info:', err);
    content.innerHTML = `<p class="error">Failed to load billing info: ${escapeHtml(String(err))}</p>`;
  }
}

/** Render the entire billing panel content from the API response. */
function renderBilling(host: HTMLElement, d: CreditsResponse): void {
  host.innerHTML = '';

  host.appendChild(renderBalanceSection(d));
  host.appendChild(renderUsageSection(d));

  // Transaction history is only rendered when there's at least one row.
  // The empty state is "no Transaction History section at all", not an
  // empty section with a "No transactions yet" placeholder.
  const txs = d.transactions || [];
  if (txs.length > 0) {
    host.appendChild(renderTransactionsSection(txs));
  }
}

/** Section 1: balance + (when below baseline) the friendly note. */
function renderBalanceSection(d: CreditsResponse): HTMLElement {
  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';

  const h = document.createElement('h4');
  h.textContent = 'Balance';
  wrap.appendChild(h);

  const bal = document.createElement('p');
  bal.className = 'billing-balance-amount';
  bal.textContent = d.formatted_balance || `${d.balance_usd_microcents} microcents`;
  if (d.balance_usd_microcents < 0) bal.classList.add('negative');
  wrap.appendChild(bal);

  // Show a short note here ONLY when the user is below the free baseline
  // (the server's runway "note" field is the signal). Negative-balance and
  // positive-balance runway info both move to the Current Storage section
  // below, where they sit next to the projected cost they relate to.
  if (d.credits_runway?.note && (d.current_usage?.billable_bytes ?? 0) === 0) {
    const note = document.createElement('p');
    note.className = 'billing-below-baseline';
    note.textContent = d.credits_runway.note;
    wrap.appendChild(note);
  }

  // Top Up Balance Button
  if (d.payments?.enabled) {
    const btnContainer = document.createElement('div');
    btnContainer.style.marginTop = '1rem';

    const topUpBtn = document.createElement('button');
    topUpBtn.type = 'button';
    topUpBtn.className = 'btn';
    topUpBtn.style.backgroundColor = 'var(--biolum)';
    topUpBtn.style.color = 'var(--depth-1)';
    topUpBtn.style.border = 'none';
    topUpBtn.style.padding = '0.5rem 1rem';
    topUpBtn.style.borderRadius = '4px';
    topUpBtn.style.cursor = 'pointer';
    topUpBtn.style.fontFamily = 'monospace';
    topUpBtn.style.fontWeight = 'bold';
    topUpBtn.textContent = 'Top Up Balance';
    
    topUpBtn.onclick = () => showTopUpModal(d.payments!);
    btnContainer.appendChild(topUpBtn);
    wrap.appendChild(btnContainer);
  }

  return wrap;
}

/** Section 2: current storage + (when above baseline) projected cost + runway. */
function renderUsageSection(d: CreditsResponse): HTMLElement {
  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';

  const h = document.createElement('h4');
  h.textContent = 'Current Storage and Cost';
  wrap.appendChild(h);

  const cu = d.current_usage;
  if (!cu) {
    const p = document.createElement('p');
    p.textContent = 'Storage usage not available.';
    wrap.appendChild(p);
    return wrap;
  }

  const dl = document.createElement('dl');
  dl.className = 'billing-usage-grid';

  appendKV(dl, 'Storage used', formatBytes(cu.total_storage_bytes));
  appendKV(dl, 'Free baseline', formatBytes(cu.free_baseline_bytes));
  appendKV(dl, 'Billable usage', formatBytes(cu.billable_bytes));

  if (cu.billable_bytes > 0) {
    appendKV(dl, 'Your projected cost', cu.current_cost_per_month_usd_approx + '/month');

    // Estimated runway (positive balance only; negative balances render
    // the "Charges continue to accumulate" note from the server). Sits
    // here under the projected cost so the relationship between rate, usage,
    // and runway is visually direct.
    const runway = d.credits_runway;
    if (runway && typeof runway.estimated_hours_remaining === 'number' && runway.estimated_hours_remaining > 0) {
      appendKV(dl, 'Estimated runway', formatHoursFriendly(runway.estimated_hours_remaining));
    } else if (runway?.note && d.balance_usd_microcents < 0) {
      // Negative balance: show the server's note (e.g. "Charges continue
      // to accumulate.") inline as a runway value rather than a separate
      // section, so it stays grouped with the projected cost.
      appendKV(dl, 'Estimated runway', runway.note);
    }
  }

  wrap.appendChild(dl);
  return wrap;
}

/** Section 3: transaction history table. Only called when txs.length > 0. */
function renderTransactionsSection(txs: Transaction[]): HTMLElement {
  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';

  const h = document.createElement('h4');
  h.textContent = 'Transaction History';
  wrap.appendChild(h);

  const table = document.createElement('table');
  table.className = 'billing-tx-table';

  const thead = document.createElement('thead');
  thead.innerHTML =
    '<tr><th>Date</th><th>Type</th><th>Amount</th><th>Balance</th><th>Reason</th></tr>';
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  for (const t of txs) {
    const tr = document.createElement('tr');
    tr.className = `billing-tx-${escapeHtml(t.transaction_type)}`;

    const date = document.createElement('td');
    date.textContent = formatDate(t.created_at);
    tr.appendChild(date);

    const type = document.createElement('td');
    type.textContent = formatTransactionType(t.transaction_type);
    tr.appendChild(type);

    const amount = document.createElement('td');
    amount.className = 'billing-tx-amount';
    amount.textContent = t.formatted_amount || `${t.amount_usd_microcents}`;
    if (t.amount_usd_microcents < 0) amount.classList.add('negative');
    tr.appendChild(amount);

    const balAfter = document.createElement('td');
    balAfter.className = 'billing-tx-balance';
    balAfter.textContent = t.formatted_balance_after || `${t.balance_after_usd_microcents}`;
    if (t.balance_after_usd_microcents < 0) balAfter.classList.add('negative');
    tr.appendChild(balAfter);

    const reason = document.createElement('td');
    let r = t.reason || '';
    if ((t.transaction_type === 'gift' || t.transaction_type === 'adjustment') && t.admin_username) {
      r += ` (by ${t.admin_username})`;
    }
    reason.textContent = r;
    tr.appendChild(reason);

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);

  const scroll = document.createElement('div');
  scroll.className = 'billing-tx-scroll';
  scroll.appendChild(table);
  wrap.appendChild(scroll);

  return wrap;
}

// Helpers

function appendKV(dl: HTMLElement, k: string, v: string): void {
  const dt = document.createElement('dt');
  dt.textContent = k;
  const dd = document.createElement('dd');
  dd.textContent = v;
  dl.appendChild(dt);
  dl.appendChild(dd);
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(2)} ${units[i]}`;
}

function formatHoursFriendly(hours: number): string {
  if (hours <= 0) return '0 hours';
  if (hours < 48) return `${hours} hours`;
  const days = hours / 24;
  if (days < 90) return `~${days.toFixed(0)} days`;
  const months = days / 30;
  if (months < 24) return `~${months.toFixed(0)} months`;
  const years = days / 365;
  return `~${years.toFixed(1)} years`;
}

function formatDate(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function formatTransactionType(type: string): string {
  if (type === 'payment') return 'Top-up';
  return type;
}

/**
 * Handle return from an external BTCPay checkout tab (/billing?success=true&invoice=...).
 * Opens the billing panel, polls invoice status, and strips checkout query parameters.
 */
export async function handleBillingCheckoutReturn(): Promise<boolean> {
  const url = new URL(window.location.href);
  const success = url.searchParams.get('success') === 'true';
  const invoiceID = url.searchParams.get('invoice');
  if (!success || !invoiceID) {
    return false;
  }

  const cleanPath = url.pathname === '/billing' ? '/' : url.pathname;
  window.history.replaceState({}, '', cleanPath + url.hash);

  const panel = document.getElementById('billing-panel');
  if (panel) {
    panel.classList.remove('hidden');
    closeOtherPanels('billing-panel');
  }

  const content = document.getElementById('billing-panel-content');
  if (content) {
    content.innerHTML = '<p>Confirming payment…</p>';
  }

  await pollInvoiceStatus(invoiceID, 30, 2000);
  await loadBilling();

  const { showSuccess } = await import('./messages');
  showSuccess('Payment received. Your balance has been updated.');
  return true;
}

async function pollInvoiceStatus(invoiceID: string, maxAttempts: number, intervalMs: number): Promise<void> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const response = await authenticatedFetch(
        `/api/billing/invoice/${encodeURIComponent(invoiceID)}`,
        { method: 'GET' },
      );
      if (response.ok) {
        const result = await response.json();
        const data = (result.data || result) as { status?: string };
        if (data.status === 'paid') {
          return;
        }
      }
    } catch (err) {
      console.warn('Invoice status poll failed:', err);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** Show the Top Up payment modal and handle invoice generation + iframe embedding. */
function showTopUpModal(cfg: PaymentsConfig): void {
  const overlayId = 'arkfile-topup-modal-overlay';
  
  // Remove any existing topup modals
  const existing = document.getElementById(overlayId);
  if (existing) {
    existing.remove();
  }

  const overlay = document.createElement('div');
  overlay.id = overlayId;
  overlay.className = 'password-modal-overlay';
  overlay.style.position = 'fixed';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100%';
  overlay.style.height = '100%';
  overlay.style.backgroundColor = 'color-mix(in srgb, var(--depth-1) 80%, transparent)';
  overlay.style.display = 'flex';
  overlay.style.justifyContent = 'center';
  overlay.style.alignItems = 'center';
  overlay.style.zIndex = '2000';

  const modal = document.createElement('div');
  modal.className = 'password-modal';
  modal.style.backgroundColor = 'var(--depth-3)';
  modal.style.border = '1px solid var(--current-2)';
  modal.style.borderRadius = '8px';
  modal.style.padding = '24px';
  modal.style.maxWidth = '550px';
  modal.style.width = '92%';
  modal.style.boxShadow = '0 4px 20px color-mix(in srgb, var(--depth-1) 80%, transparent)';

  const header = document.createElement('div');
  header.className = 'password-modal-header';
  header.style.display = 'flex';
  header.style.justifyContent = 'space-between';
  header.style.alignItems = 'center';
  header.style.marginBottom = '1.5rem';

  const title = document.createElement('h2');
  title.style.margin = '0';
  title.style.color = 'var(--salt)';
  title.style.fontFamily = 'monospace';
  title.style.fontSize = '1.5rem';
  title.textContent = 'Top Up Balance';

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'password-modal-close';
  closeBtn.innerHTML = '&times;';
  closeBtn.style.background = 'none';
  closeBtn.style.border = 'none';
  closeBtn.style.color = 'var(--foam-2)';
  closeBtn.style.fontSize = '1.5rem';
  closeBtn.style.cursor = 'pointer';
  closeBtn.onclick = () => {
    overlay.remove();
    loadBilling().catch(err => console.error(err));
  };

  header.appendChild(title);
  header.appendChild(closeBtn);
  modal.appendChild(header);

  const body = document.createElement('div');
  body.className = 'password-modal-body';

  const desc = document.createElement('p');
  desc.style.color = 'var(--foam-1)';
  desc.style.marginBottom = '1rem';
  desc.textContent = `Enter an amount in USD to generate a BTCPay Server invoice. Payments can be made with Bitcoin, Lightning, Monero, or credit cards if enabled.`;
  body.appendChild(desc);

  const form = document.createElement('form');
  form.id = 'topup-form';

  const field = document.createElement('div');
  field.className = 'password-modal-field';
  field.style.marginBottom = '1rem';

  const label = document.createElement('label');
  label.htmlFor = 'topup-amount-input';
  label.style.display = 'block';
  label.style.color = 'var(--foam-2)';
  label.style.marginBottom = '0.5rem';
  label.textContent = `Amount (USD): Min $${cfg.min_top_up}, Max $${cfg.max_top_up}`;
  field.appendChild(label);

  const input = document.createElement('input');
  input.type = 'number';
  input.id = 'topup-amount-input';
  input.className = 'password-modal-input';
  input.step = '0.01';
  input.min = cfg.min_top_up;
  input.max = cfg.max_top_up;
  input.value = '10.00';
  input.required = true;
  input.style.width = '100%';
  input.style.backgroundColor = 'var(--depth-2)';
  input.style.border = '1px solid var(--current-1)';
  input.style.color = 'var(--salt)';
  input.style.padding = '0.5rem';
  input.style.borderRadius = '4px';
  input.style.fontFamily = 'monospace';
  field.appendChild(input);

  form.appendChild(field);

  const errorEl = document.createElement('p');
  errorEl.id = 'topup-error';
  errorEl.style.color = 'var(--coral)';
  errorEl.style.marginTop = '0.5rem';
  errorEl.style.display = 'none';
  form.appendChild(errorEl);

  const footer = document.createElement('div');
  footer.className = 'password-modal-footer';
  footer.style.display = 'flex';
  footer.style.justifyContent = 'flex-end';
  footer.style.gap = '10px';
  footer.style.marginTop = '1.5rem';

  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'password-modal-btn password-modal-btn-cancel';
  cancelBtn.textContent = 'Cancel';
  cancelBtn.style.padding = '0.5rem 1rem';
  cancelBtn.style.cursor = 'pointer';
  cancelBtn.onclick = () => {
    overlay.remove();
  };

  const submitBtn = document.createElement('button');
  submitBtn.type = 'submit';
  submitBtn.className = 'password-modal-btn password-modal-btn-submit';
  submitBtn.textContent = 'Generate Invoice';
  submitBtn.style.padding = '0.5rem 1rem';
  submitBtn.style.cursor = 'pointer';

  footer.appendChild(cancelBtn);
  footer.appendChild(submitBtn);
  form.appendChild(footer);
  body.appendChild(form);
  modal.appendChild(body);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  form.onsubmit = async (e) => {
    e.preventDefault();
    errorEl.style.display = 'none';
    submitBtn.disabled = true;
    cancelBtn.disabled = true;
    submitBtn.textContent = 'Creating Invoice...';

    const amountStr = input.value;

    try {
      const response = await authenticatedFetch('/api/billing/invoice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount_usd: amountStr }),
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.message || `Server returned status ${response.status}`);
      }

      const res = await response.json();
      const invoiceData = res.data;

      // Replace form/body content with an iframe
      body.innerHTML = '';
      
      const iframeContainer = document.createElement('div');
      iframeContainer.style.width = '100%';
      iframeContainer.style.height = '460px';
      iframeContainer.style.position = 'relative';

      const iframe = document.createElement('iframe');
      iframe.src = invoiceData.checkout_url;
      iframe.style.width = '100%';
      iframe.style.height = '100%';
      iframe.style.border = 'none';
      iframe.style.borderRadius = '8px';
      iframe.style.backgroundColor = 'var(--depth-4)';

      iframeContainer.appendChild(iframe);
      body.appendChild(iframeContainer);
    } catch (err) {
      console.error('Invoice creation failed:', err);
      errorEl.textContent = `Invoice generation failed: ${escapeHtml(String(err))}`;
      errorEl.style.display = 'block';
      submitBtn.disabled = false;
      cancelBtn.disabled = false;
      submitBtn.textContent = 'Generate Invoice';
    }
  };
}
