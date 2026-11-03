import { useState, type FormEvent } from 'react';
import type { User } from './Profile';

export function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const res = await fetch('/api/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
    });
    if (!res.ok) {
      setError('Wrong username or password.');
      return;
    }
    onLogin(await res.json());
  }

  return (
    <form className="login" onSubmit={handleSubmit}>
      <h2>Sign in</h2>
      <label>
        Username
        <input name="username" autoComplete="username" required />
      </label>
      <label>
        Password
        <input
          type="password"
          name="password"
          autoComplete="current-password"
          data-sentry-mask
          required
        />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit">Sign in</button>
    </form>
  );
}
