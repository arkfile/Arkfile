/**
 * Billing panel UI for storage credits / usage metering.
 *
 * Renders one inline panel (matching the security-settings + contact-info
 * pattern) with three sections:
 *
 *   1. Subscription Plans   -- public catalog + Subscribe, only when
 *                              subscriptions are enabled and the user is
 *                              not already subscribed.
 *   2. Your Subscription    -- current plan + Update Subscription (processor
 *                              portal) when billing_mode is subscribed.
 *   3. Balance              -- signed four-decimal USD; below-baseline note.
 *   4. Current Storage and  -- storage used / free baseline / billable bytes;
 *      Cost                    when there is billable usage, also projected
 *                              monthly cost and estimated runway.
 *   5. Transaction History  -- only rendered when there is at least one
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

import { authenticatedFetch, refreshToken, isAuthenticated, validateToken } from '../utils/auth';
import { formatBytes } from '../utils/format.js';
import { closeNavInlinePanelsExcept } from './sections.js';
import { ensurePasswordModalStyles } from './password-modal.js';

/** Toggle the billing panel visibility, loading data on open. */
export async function toggleBillingPanel(): Promise<void> {
  const panel = document.getElementById('billing-panel');
  if (!panel) return;

  const isHidden = panel.classList.contains('hidden');
  panel.classList.toggle('hidden');

  // Mutual exclusion with the other inline panels (incl. download integrity).
  if (isHidden) {
    closeNavInlinePanelsExcept('billing-panel');
    await loadBilling();
  }
}

interface CurrentUsage {
  total_storage_bytes: number;
  free_baseline_bytes: number;
  billable_bytes: number;
  effective_storage_limit_bytes?: number;
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
  billing_mode?: string;
  current_usage?: CurrentUsage & { effective_storage_limit_bytes?: number };
  credits_runway?: CreditsRunway;
  transactions?: Transaction[];
  payments?: PaymentsConfig;
  subscription?: SubscriptionInfo;
}

interface SubscriptionInfo {
  enabled: boolean;
  status?: string;
  plan_id?: string;
  plan_name?: string;
  price_usd?: string;
  baseline_storage_bytes?: number;
  plan_storage_bytes?: number;
  effective_storage_limit_bytes?: number;
  current_period_end?: string;
  cancel_at_period_end?: boolean;
  source?: string;
}

interface SubscriptionPlan {
  plan_id: string;
  name: string;
  price_usd_cents: number;
  storage_limit_bytes: number;
  description?: string;
}

/** Fetch /api/credits and render the panel. */
export async function loadBilling(): Promise<void> {
  const content = document.getElementById('billing-panel-content');
  if (!content) return;
  content.innerHTML = '<p>Loading...</p>';

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
    const { fetchOobPayments, renderOobPaymentsSection } = await import('./oob-payments.js');
    const oob = await fetchOobPayments();
    const oobSection = oob ? renderOobPaymentsSection(oob) : null;
    renderBilling(content, data, oobSection);
  } catch (err) {
    console.error('Failed to load billing info:', err);
    content.innerHTML = `<p class="error">Failed to load billing info: ${escapeHtml(String(err))}</p>`;
  }
}

/** Render the entire billing panel content from the API response. */
function renderBilling(
  host: HTMLElement,
  d: CreditsResponse,
  oobSection: HTMLElement | null,
): void {
  host.innerHTML = '';

  const isSubscribed = d.billing_mode === 'subscribed';
  if (d.subscription?.enabled) {
    if (isSubscribed) {
      host.appendChild(renderCurrentSubscriptionSection(d));
    } else {
      host.appendChild(renderAvailablePlansSection());
    }
  }

  if (!isSubscribed) {
    host.appendChild(renderBalanceSection(d));
    host.appendChild(renderUsageSection(d));
    if (oobSection) {
      host.appendChild(oobSection);
    }
    const txs = d.transactions || [];
    if (txs.length > 0) {
      host.appendChild(renderTransactionsSection(txs));
    }
  } else {
    host.appendChild(renderSubscribedUsageSection(d));
  }
}

function renderAvailablePlansSection(): HTMLElement {
  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';
  const h = document.createElement('h4');
  h.textContent = 'Subscription Plans';
  wrap.appendChild(h);
  void loadAvailablePlans(wrap);
  return wrap;
}

function renderCurrentSubscriptionSection(d: CreditsResponse): HTMLElement {
  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';
  const h = document.createElement('h4');
  h.textContent = 'Your Subscription';
  wrap.appendChild(h);

  const sub = d.subscription;
  if (!sub?.status) {
    return wrap;
  }

  const p = document.createElement('p');
  p.textContent = `${sub.plan_name || sub.plan_id} (${sub.price_usd ? '$' + sub.price_usd + '/mo' : ''}) -- ${sub.status}`;
  wrap.appendChild(p);
  if (sub.current_period_end) {
    const renew = document.createElement('p');
    renew.textContent = sub.cancel_at_period_end
      ? `Active until ${formatDate(sub.current_period_end)} (canceling)`
      : `Renews ${formatDate(sub.current_period_end)}`;
    wrap.appendChild(renew);
  }
  if (sub.source === 'bridge') {
    const updateBtn = document.createElement('button');
    updateBtn.type = 'button';
    updateBtn.className = 'btn';
    updateBtn.textContent = 'Update Subscription';
    updateBtn.onclick = () => void openSubscriptionPortal();
    wrap.appendChild(updateBtn);
  }
  return wrap;
}

async function loadAvailablePlans(host: HTMLElement): Promise<void> {
  const list = document.createElement('div');
  list.className = 'billing-plans-list';
  host.appendChild(list);
  try {
    const resp = await authenticatedFetch('/api/subscriptions/plans', { method: 'GET' });
    if (!resp.ok) throw new Error(String(resp.status));
    const body = await resp.json();
    const plans = (body.plans || []) as SubscriptionPlan[];
    if (plans.length === 0) {
      list.textContent = 'No plans available.';
      return;
    }
    for (const plan of plans) {
      const card = document.createElement('div');
      card.className = 'billing-plan-card';
      card.innerHTML = `<strong>${escapeHtml(plan.name)}</strong> -- $${(plan.price_usd_cents / 100).toFixed(2)}/mo -- ${formatBytes(plan.storage_limit_bytes)}`;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn';
      btn.textContent = 'Subscribe';
      btn.onclick = () => void startSubscriptionCheckout(plan.plan_id);
      card.appendChild(btn);
      list.appendChild(card);
    }
  } catch (err) {
    list.textContent = `Failed to load plans: ${String(err)}`;
  }
}

async function startSubscriptionCheckout(planId: string): Promise<void> {
  const resp = await authenticatedFetch('/api/subscriptions/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plan_id: planId }),
  });
  if (!resp.ok) {
    alert('Could not start checkout.');
    return;
  }
  const body = await resp.json();
  const url = body.data?.checkout_url;
  if (url) window.location.href = url;
}

async function openSubscriptionPortal(): Promise<void> {
  const resp = await authenticatedFetch('/api/subscriptions/portal', { method: 'POST' });
  if (!resp.ok) {
    alert('Could not open billing portal.');
    return;
  }
  const body = await resp.json();
  const url = body.data?.portal_url;
  if (url) window.location.href = url;
}

function renderSubscribedUsageSection(d: CreditsResponse): HTMLElement {
  const wrap = document.createElement('section');
  wrap.className = 'billing-panel-section';
  const h = document.createElement('h4');
  h.textContent = 'Storage';
  wrap.appendChild(h);
  const cu = d.current_usage;
  const dl = document.createElement('dl');
  dl.className = 'billing-usage-grid';
  if (cu) {
    appendKV(dl, 'Storage used', formatBytes(cu.total_storage_bytes));
    appendKV(dl, 'Upload cap', formatBytes(cu.effective_storage_limit_bytes ?? cu.free_baseline_bytes));
  }
  appendKV(dl, 'PAYG balance (frozen)', d.formatted_balance);
  wrap.appendChild(dl);
  return wrap;
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

  // Top Up Balance Button (PAYG only; hidden while subscribed)
  if (d.payments?.enabled && d.billing_mode !== 'subscribed') {
    const btnContainer = document.createElement('div');
    btnContainer.style.marginTop = '1rem';

    const topUpBtn = document.createElement('button');
    topUpBtn.type = 'button';
    topUpBtn.className = 'btn';
    topUpBtn.style.backgroundColor = 'var(--biolum)';
    topUpBtn.style.color = 'var(--depth-1)';
    topUpBtn.style.border = 'none';
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
  if (typeof cu.effective_storage_limit_bytes === 'number' && cu.effective_storage_limit_bytes > 0) {
    appendKV(dl, 'Upload cap', formatBytes(cu.effective_storage_limit_bytes));
  }
  if (cu.rate_human) {
    appendKV(dl, 'Rate', cu.rate_human);
  }

  if (cu.billable_bytes > 0) {
    appendKV(dl, 'Your projected cost', cu.current_cost_per_month_usd_approx + '/month');

    // Estimated runway (positive balance only; negative balances render
    // the "Charges continue to accumulate" note from the server). Sits
    // here under the projected cost so the relationship between rate, usage,
    // and runway is visually direct.
    const runway = d.credits_runway;
    if (runway && typeof runway.estimated_hours_remaining === 'number' && runway.estimated_hours_remaining > 0) {
      appendKV(dl, 'Estimated runway', formatHoursFriendly(runway.estimated_hours_remaining));
      if (runway.estimated_runs_out_at_approx) {
        appendKV(dl, 'Estimated run-out', runway.estimated_runs_out_at_approx);
      }
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

/** sessionStorage key for a top-up whose checkout page is open in another tab. */
export const PENDING_INVOICE_STORAGE_KEY = 'arkfile_pending_invoice';

/** Invoice status polling while the top-up progress view is open. */
const CHECKOUT_POLL_INTERVAL_MS = 5000;
const CHECKOUT_POLL_MAX_MS = 2 * 60 * 60 * 1000;

export interface InvoiceStatusData {
  invoice_id: string;
  status: string;
  amount_usd_microcents?: number;
  checkout_url?: string;
}

export type InvoiceWatchOutcome =
  | 'paid'
  | 'expired'
  | 'failed'
  | 'not_found'
  | 'session_ended'
  | 'timeout'
  | 'cancelled';

export function isFinalInvoiceStatus(status: string): boolean {
  return status === 'paid' || status === 'expired' || status === 'failed';
}

/** User-facing text for each local invoice status. */
export function describeInvoiceStatus(status: string): string {
  switch (status) {
    case 'pending':
      return 'Waiting for payment. Complete the payment on the payment page. This window updates automatically.';
    case 'confirming':
      return 'Payment detected. Waiting for network confirmation. This can take from a few minutes to about an hour. Your balance is credited automatically once the payment is confirmed.';
    case 'paid':
      return 'Payment confirmed. Your balance has been credited.';
    case 'expired':
      return 'This invoice expired before a payment was confirmed. No balance was credited. If you sent a payment after the invoice expired, contact the administrator.';
    case 'failed':
      return 'This invoice failed or was refunded. No balance was credited.';
    default:
      return 'Checking payment status...';
  }
}

/** Only http(s) checkout links are rendered. */
export function safeCheckoutURL(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

export interface InvoiceWatchOptions {
  intervalMs?: number;
  maxMs?: number;
  onStatus?: (data: InvoiceStatusData) => void;
  isCancelled?: () => boolean;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

/**
 * Polls GET /api/billing/invoice/{id} until the invoice reaches a final status,
 * the session ends, the caller cancels, or maxMs elapses. The server refreshes
 * open invoices from the payment provider on each poll (throttled server-side).
 */
export async function watchInvoiceStatus(
  invoiceID: string,
  opts: InvoiceWatchOptions = {},
): Promise<InvoiceWatchOutcome> {
  const intervalMs = opts.intervalMs ?? CHECKOUT_POLL_INTERVAL_MS;
  const maxMs = opts.maxMs ?? CHECKOUT_POLL_MAX_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.now ?? Date.now;
  const deadline = now() + maxMs;
  let lastStatus = '';

  while (true) {
    if (opts.isCancelled?.()) return 'cancelled';
    try {
      const response = await authenticatedFetch(
        `/api/billing/invoice/${encodeURIComponent(invoiceID)}`,
        { method: 'GET' },
      );
      if (response.ok) {
        const result = await response.json();
        const data = (result.data || result) as InvoiceStatusData;
        if (opts.isCancelled?.()) return 'cancelled';
        if (data.status !== lastStatus) {
          lastStatus = data.status;
          opts.onStatus?.(data);
        }
        if (isFinalInvoiceStatus(data.status)) {
          return data.status as InvoiceWatchOutcome;
        }
      } else if (response.status === 401) {
        return 'session_ended';
      } else if (response.status === 404) {
        return 'not_found';
      }
    } catch (err) {
      console.warn('Invoice status poll failed:', err);
    }
    if (now() >= deadline) return 'timeout';
    await sleep(intervalMs);
  }
}

async function ensureSessionForBillingPoll(): Promise<boolean> {
  if (isAuthenticated()) {
    const valid = await validateToken();
    if (valid) {
      return true;
    }
  }
  const refreshed = await refreshToken();
  if (!refreshed.ok) {
    return false;
  }
  return validateToken();
}

/**
 * Reopens the top-up progress view after a reload or login when a checkout was
 * in progress in this tab. Does not wait for the payment to settle.
 */
export async function resumePendingBillingCheckout(): Promise<boolean> {
  const invoiceID = sessionStorage.getItem(PENDING_INVOICE_STORAGE_KEY);
  if (!invoiceID) {
    return false;
  }
  if (!(await ensureSessionForBillingPoll())) {
    return false;
  }

  let data: InvoiceStatusData | null = null;
  try {
    const response = await authenticatedFetch(
      `/api/billing/invoice/${encodeURIComponent(invoiceID)}`,
      { method: 'GET' },
    );
    if (response.ok) {
      const result = await response.json();
      data = (result.data || result) as InvoiceStatusData;
    } else if (response.status === 404) {
      sessionStorage.removeItem(PENDING_INVOICE_STORAGE_KEY);
      return false;
    }
  } catch (err) {
    console.warn('Failed to load pending invoice:', err);
  }
  if (!data) {
    return false;
  }

  const panel = document.getElementById('billing-panel');
  if (panel) {
    panel.classList.remove('hidden');
    closeNavInlinePanelsExcept('billing-panel');
  }
  void loadBilling();

  const shell = createTopUpShell();
  renderCheckoutProgress(shell, data);
  return true;
}

/** Poll /api/subscriptions/me after returning from bridge checkout. */
export async function resumePendingSubscriptionCheckout(): Promise<boolean> {
  const params = new URLSearchParams(window.location.search);
  if (params.get('subscription') !== 'return') {
    return false;
  }
  if (!(await ensureSessionForBillingPoll())) {
    return false;
  }
  const panel = document.getElementById('billing-panel');
  if (panel) {
    panel.classList.remove('hidden');
    closeNavInlinePanelsExcept('billing-panel');
  }
  const content = document.getElementById('billing-panel-content');
  if (content) {
    content.innerHTML = '<p>Confirming subscription...</p>';
  }
  for (let i = 0; i < 30; i++) {
    const resp = await authenticatedFetch('/api/subscriptions/me', { method: 'GET' });
    if (resp.ok) {
      const body = await resp.json();
      const data = body.data || body;
      const st = data?.subscription?.status;
      if (st === 'active' || st === 'trialing') {
        await loadBilling();
        const { showSuccess } = await import('./messages');
        showSuccess('Subscription active.');
        const clean = new URL(window.location.href);
        clean.searchParams.delete('subscription');
        clean.searchParams.delete('checkout_id');
        window.history.replaceState({}, '', clean.pathname + clean.search + clean.hash);
        return true;
      }
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  await loadBilling();
  return true;
}

interface TopUpShell {
  overlay: HTMLElement;
  body: HTMLElement;
  /** Registers cleanup to run when the modal closes. */
  onClose: (fn: () => void) => void;
  close: () => void;
  isOpen: () => boolean;
}

const TOP_UP_OVERLAY_ID = 'arkfile-topup-modal-overlay';

/** Builds the empty top-up modal (header + body) and attaches it to the page. */
function createTopUpShell(): TopUpShell {
  const existing = document.getElementById(TOP_UP_OVERLAY_ID);
  if (existing) {
    existing.dispatchEvent(new CustomEvent('arkfile-topup-close'));
    existing.remove();
  }

  ensurePasswordModalStyles();

  const overlay = document.createElement('div');
  overlay.id = TOP_UP_OVERLAY_ID;
  overlay.className = 'password-modal-overlay';
  overlay.style.zIndex = '2000';

  const modal = document.createElement('div');
  modal.className = 'password-modal';
  modal.style.backgroundColor = 'var(--depth-3)';
  modal.style.border = '1px solid var(--current-2)';
  modal.style.borderRadius = '8px';
  modal.style.padding = '24px';
  modal.style.maxWidth = '550px';
  modal.style.width = '92%';
  modal.style.maxHeight = '90vh';
  modal.style.overflowY = 'auto';
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
  closeBtn.setAttribute('aria-label', 'Close');
  closeBtn.textContent = 'x';

  const cleanups: Array<() => void> = [];
  let open = true;
  const close = () => {
    if (!open) return;
    open = false;
    document.removeEventListener('keydown', onKey);
    for (const fn of cleanups) {
      try {
        fn();
      } catch (err) {
        console.warn('Top-up cleanup failed:', err);
      }
    }
    if (document.body.contains(overlay)) {
      overlay.remove();
    }
    loadBilling().catch((err) => console.error(err));
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') close();
  };
  document.addEventListener('keydown', onKey);
  closeBtn.onclick = close;
  overlay.addEventListener('arkfile-topup-close', close);

  header.appendChild(title);
  header.appendChild(closeBtn);
  modal.appendChild(header);

  const body = document.createElement('div');
  body.className = 'password-modal-body';
  modal.appendChild(body);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  return {
    overlay,
    body,
    onClose: (fn) => cleanups.push(fn),
    close,
    isOpen: () => open,
  };
}

/** Show the Top Up modal: amount form, then the checkout progress view. */
function showTopUpModal(cfg: PaymentsConfig): void {
  const shell = createTopUpShell();
  const body = shell.body;

  const desc = document.createElement('p');
  desc.style.color = 'var(--foam-1)';
  desc.style.marginBottom = '1rem';
  desc.textContent = 'Enter an amount in USD to generate a payment invoice. You can pay with Bitcoin or Monero on the payment page.';
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
  cancelBtn.style.cursor = 'pointer';
  cancelBtn.onclick = shell.close;

  const submitBtn = document.createElement('button');
  submitBtn.type = 'submit';
  submitBtn.className = 'password-modal-btn password-modal-btn-submit';
  submitBtn.textContent = 'Generate Invoice';
  submitBtn.style.cursor = 'pointer';

  footer.appendChild(cancelBtn);
  footer.appendChild(submitBtn);
  form.appendChild(footer);
  body.appendChild(form);

  const paymentRequestID = crypto.randomUUID();
  form.onsubmit = async (e) => {
    e.preventDefault();
    errorEl.style.display = 'none';
    submitBtn.disabled = true;
    cancelBtn.disabled = true;
    submitBtn.textContent = 'Creating Invoice...';

    try {
      const response = await authenticatedFetch('/api/billing/invoice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount_usd: input.value, request_id: paymentRequestID }),
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.message || `Server returned status ${response.status}`);
      }

      const res = await response.json();
      const invoiceData = res.data as InvoiceStatusData;
      if (!invoiceData?.invoice_id) {
        throw new Error('Server did not return an invoice');
      }
      if (!shell.isOpen()) return;
      renderCheckoutProgress(shell, {
        ...invoiceData,
        invoice_id: String(invoiceData.invoice_id),
        status: invoiceData.status || 'pending',
      });
    } catch (err) {
      console.error('Invoice creation failed:', err);
      errorEl.textContent = `Invoice generation failed: ${String(err)}`;
      errorEl.style.display = 'block';
      submitBtn.disabled = false;
      cancelBtn.disabled = false;
      submitBtn.textContent = 'Generate Invoice';
    }
  };
}

/**
 * Replaces the modal body with the checkout link and live status. While this
 * view is open the Account Key idle lock is held, so paying in another tab
 * does not lock the user out of their files.
 */
function renderCheckoutProgress(shell: TopUpShell, invoice: InvoiceStatusData): void {
  const body = shell.body;
  body.innerHTML = '';
  sessionStorage.setItem(PENDING_INVOICE_STORAGE_KEY, invoice.invoice_id);

  if (typeof invoice.amount_usd_microcents === 'number') {
    const amount = document.createElement('p');
    amount.style.color = 'var(--foam-1)';
    amount.textContent = `Invoice amount: $${(invoice.amount_usd_microcents / 100_000_000).toFixed(2)} USD`;
    body.appendChild(amount);
  }

  const linkWrap = document.createElement('p');
  const checkoutURL = safeCheckoutURL(invoice.checkout_url);
  const link = document.createElement('a');
  link.id = 'topup-checkout-link';
  link.className = 'btn';
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = 'Open payment page';
  if (checkoutURL) {
    link.href = checkoutURL;
  }
  linkWrap.appendChild(link);
  body.appendChild(linkWrap);

  const hint = document.createElement('p');
  hint.style.color = 'var(--foam-2)';
  hint.style.fontSize = '0.9rem';
  hint.textContent = 'The payment page opens in a new tab. Keep this window open; it updates when your payment is detected and confirmed.';
  body.appendChild(hint);

  const statusEl = document.createElement('p');
  statusEl.id = 'topup-status';
  statusEl.setAttribute('role', 'status');
  statusEl.setAttribute('aria-live', 'polite');
  statusEl.dataset.status = invoice.status;
  statusEl.style.color = 'var(--salt)';
  statusEl.textContent = describeInvoiceStatus(invoice.status);
  body.appendChild(statusEl);

  const footer = document.createElement('div');
  footer.className = 'password-modal-footer';
  footer.style.display = 'flex';
  footer.style.justifyContent = 'flex-end';
  footer.style.marginTop = '1.5rem';
  const doneBtn = document.createElement('button');
  doneBtn.type = 'button';
  doneBtn.className = 'password-modal-btn password-modal-btn-cancel';
  doneBtn.textContent = 'Close';
  doneBtn.onclick = shell.close;
  footer.appendChild(doneBtn);
  body.appendChild(footer);

  const setStatus = (status: string) => {
    statusEl.dataset.status = status;
    statusEl.textContent = describeInvoiceStatus(status);
    if (isFinalInvoiceStatus(status)) {
      linkWrap.remove();
      hint.remove();
    }
  };

  if (isFinalInvoiceStatus(invoice.status)) {
    setStatus(invoice.status);
    sessionStorage.removeItem(PENDING_INVOICE_STORAGE_KEY);
    return;
  }

  let cancelled = false;
  let wake: (() => void) | null = null;
  const onVisible = () => {
    if (document.visibilityState === 'visible' && wake) wake();
  };
  document.addEventListener('visibilitychange', onVisible);

  const holdKey = async (active: boolean) => {
    const { setAccountKeyIdleLockHold } = await import('../crypto/account-key-cache.js');
    setAccountKeyIdleLockHold(active);
  };
  void holdKey(true);

  const release = () => {
    cancelled = true;
    if (wake) wake();
    document.removeEventListener('visibilitychange', onVisible);
    void holdKey(false);
  };
  shell.onClose(() => {
    release();
    sessionStorage.removeItem(PENDING_INVOICE_STORAGE_KEY);
  });

  void watchInvoiceStatus(invoice.invoice_id, {
    isCancelled: () => cancelled,
    onStatus: (data) => setStatus(data.status),
    sleep: (ms) => new Promise<void>((resolve) => {
      const timer = setTimeout(done, ms);
      function done() {
        clearTimeout(timer);
        wake = null;
        resolve();
      }
      wake = done;
    }),
  }).then((outcome) => {
    if (outcome === 'cancelled') return;
    release();
    if (outcome === 'paid' || outcome === 'expired' || outcome === 'failed' || outcome === 'not_found') {
      sessionStorage.removeItem(PENDING_INVOICE_STORAGE_KEY);
    }
    if (outcome === 'not_found') {
      statusEl.textContent = 'This invoice could not be found. No balance was credited.';
    } else if (outcome === 'timeout') {
      statusEl.textContent = 'Still waiting for confirmation. Your balance is credited automatically once the payment is confirmed. Check Billing again later.';
    } else if (outcome === 'session_ended') {
      statusEl.textContent = 'Your session ended. Log in again to check this payment.';
    }
    if (outcome === 'paid') {
      loadBilling().catch((err) => console.error(err));
    }
  });
}
