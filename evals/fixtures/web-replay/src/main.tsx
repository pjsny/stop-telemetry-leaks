import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { initAnalytics, identify } from './analytics';
import { Checkout } from './Checkout';
import { Login } from './Login';
import { Profile, type User } from './Profile';
import { startRecording } from './recorder';
import { initRum } from './rum';
import { initSentry } from './sentry';

initSentry();
initRum();
initAnalytics();
startRecording();

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [orderId, setOrderId] = useState<string | null>(null);

  if (!user) {
    return (
      <Login
        onLogin={(next) => {
          identify(next.id, next.plan);
          setUser(next);
        }}
      />
    );
  }

  return (
    <main>
      <Profile user={user} />
      {orderId ? <p>Thanks! Order {orderId} is confirmed.</p> : <Checkout totalCents={4900} onPaid={setOrderId} />}
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
