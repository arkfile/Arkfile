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
 * See docs/wip/storage-credits-v2.md §7 for the design.
 *
 * CSS hooks (defined in client/static/css/styles.css under the
 * "Billing panel" comment block):
 *   .billing-panel-section, .billing-panel-section h4
 *   .billing-balance-amount[.negative]
 *   .billing-runway, .billing-below-baseline
 *   .billing-usage-grid (dt, dd)
 *   .billing-tx-table, .billing-tx-amount[.negative], .billing-tx-balance[.negative]
 */

import { getToken } from '../utils/auth';

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

interface CreditsResponse {
  username: string;
  balance_usd_microcents: number;
  formatted_balance: string;
  current_usage?: CurrentUsage;
  credits_runway?: CreditsRunway;
  transactions?: Transaction[];
}

/** Fetch /api/credits and render the panel. */
export async function loadBilling(): Promise<void> {
  const token = getToken();
  if (!token) return;

  const content = document.getElementById('billing-panel-content');
  if (!content) return;
  content.innerHTML = '<p>Loading…</p>';

  try {
    const response = await fetch('/api/credits', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` },
    });
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
    type.textContent = t.transaction_type;
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
