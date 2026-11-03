import { useState, type FormEvent } from 'react';
import { track } from './analytics';

type Props = {
  totalCents: number;
  onPaid: (orderId: string) => void;
};

export function Checkout({ totalCents, onPaid }: Props) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    const form = new FormData(event.currentTarget);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(Object.fromEntries(form)),
      });
      if (!res.ok) throw new Error(`checkout failed: ${res.status}`);
      const { orderId } = await res.json();
      track('checkout_completed', { totalCents });
      onPaid(orderId);
    } catch {
      setError('We could not process your payment. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="checkout" onSubmit={handleSubmit}>
      <h2>Payment</h2>
      <label>
        Email for receipt
        <input type="email" name="receiptEmail" autoComplete="email" required />
      </label>
      <label>
        Card number
        <input name="cardNumber" inputMode="numeric" autoComplete="cc-number" required />
      </label>
      <div className="row">
        <label>
          Expiry
          <input name="expiry" placeholder="MM/YY" autoComplete="cc-exp" required />
        </label>
        <label>
          Security code
          <input name="cvv" inputMode="numeric" maxLength={4} autoComplete="cc-csc" required />
        </label>
      </div>
      <label>
        Promo code
        <input name="promo" autoComplete="off" />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" disabled={submitting}>
        Pay ${(totalCents / 100).toFixed(2)}
      </button>
    </form>
  );
}
