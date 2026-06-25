/**
 * Share Download Ticket client
 *
 * After a recipient decrypts the share envelope, they exchange the static
 * download token recovered from the envelope for a short-lived, entity-bound
 * download ticket. The ticket is presented as X-Share-Ticket on chunk fetches
 * and is refreshed transparently if it expires mid-download.
 *
 * This mirrors the Go CLI's share download ticket handling so both clients use
 * the same credential flow against the same server endpoint.
 */

const TICKET_ENDPOINT = (shareId: string) =>
  `/api/public/shares/${encodeURIComponent(shareId)}/ticket`;

export interface ShareTicketResponse {
  share_id: string;
  ticket: string;
  expires_in: number; // seconds
}

/**
 * Request a short-lived download ticket from the server by presenting the
 * static download token (proof of envelope decryption). Returns the ticket
 * string and its TTL in seconds.
 */
export async function requestShareTicket(
  shareId: string,
  downloadToken: string,
): Promise<ShareTicketResponse> {
  if (!shareId) throw new Error('shareId is required');
  if (!downloadToken) throw new Error('downloadToken is required');

  const response = await fetch(TICKET_ENDPOINT(shareId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ download_token: downloadToken }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(
      `Failed to obtain share download ticket (HTTP ${response.status}): ${text}`,
    );
  }
  return response.json() as Promise<ShareTicketResponse>;
}

/**
 * A small holder that caches the current ticket and refreshes it on demand.
 * Callers hand the refresh function to the streaming download manager so it
 * can re-issue transparently when a chunk fetch returns 403.
 */
export class ShareTicketHolder {
  private ticket: string | null = null;
  private expiresAt = 0; // epoch ms

  constructor(
    private readonly shareId: string,
    private readonly downloadToken: string,
  ) {}

  /** Returns a valid ticket, fetching or refreshing as needed. */
  async get(): Promise<string> {
    if (this.ticket && Date.now() < this.expiresAt) {
      return this.ticket;
    }
    return this.refresh();
  }

  /** Force a fresh ticket (used on 403 mid-download). */
  async refresh(): Promise<string> {
    const res = await requestShareTicket(this.shareId, this.downloadToken);
    this.ticket = res.ticket;
    // Refresh a bit before the server-stated expiry to avoid races.
    this.expiresAt = Date.now() + Math.max(5_000, (res.expires_in - 30) * 1000);
    return this.ticket;
  }
}
