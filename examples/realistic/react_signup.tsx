import React, { useState } from "react";

export function StudentSignup() {
  const [studentAge, setStudentAge] = useState("");

  return (
    <form action="/api/students" method="post">
      <input name="first_name" placeholder="First name" />
      <input name="last_name" placeholder="Last name" />
      <input name="guardian_phone" placeholder="Guardian phone" />
      <input name="school" placeholder="School" />
      <input name="student_age" value={studentAge} onChange={(event) => setStudentAge(event.target.value)} />
      <input name="ip_address" type="hidden" />
      <button type="submit">Create profile</button>
    </form>
  );
}
