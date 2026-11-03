export type User = {
  id: string;
  email: string;
  phone: string;
  plan: 'free' | 'plus' | 'business';
  memberSince: string;
};

export function Profile({ user }: { user: User }) {
  return (
    <section className="profile">
      <h2>Your account</h2>
      <dl>
        <dt>Email</dt>
        <dd>{user.email}</dd>
        <dt>Phone</dt>
        <dd>{user.phone}</dd>
        <dt>Plan</dt>
        <dd className="plan">{user.plan}</dd>
        <dt>Member since</dt>
        <dd>{new Date(user.memberSince).toLocaleDateString()}</dd>
      </dl>
    </section>
  );
}
