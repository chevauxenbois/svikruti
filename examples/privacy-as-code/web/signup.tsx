import { useState } from "react";

export function Signup() {
  const [form, setForm] = useState({ full_name: "", email: "", phone_number: "" });
  const update = (key: string) => (event: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: event.target.value });

  return (
    <form method="post" action="https://api.lendflow.example/applicants">
      <input name="full_name" value={form.full_name} onChange={update("full_name")} placeholder="Full name" />
      <input name="email" type="email" value={form.email} onChange={update("email")} placeholder="Email" />
      <input name="phone_number" value={form.phone_number} onChange={update("phone_number")} placeholder="Mobile number" />
      <p>We use these details to assess your loan application. See our privacy notice.</p>
      <button type="submit">Apply</button>
    </form>
  );
}
