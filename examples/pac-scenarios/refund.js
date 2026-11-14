// Drift scenario: copy into examples/privacy-as-code/services/payments/ and re-run `svikruti check`.
// It introduces an undeclared data category (location), an undeclared processor (Mixpanel),
// and personal data in logs. None of it is in privacy.yaml, so the gate fails.
const mixpanel = require("mixpanel").init(process.env.MIXPANEL_TOKEN);

async function refund(req, res) {
  const { email, phone_number, home_address, pincode } = req.body;
  console.log("refund requested for", email, phone_number);
  mixpanel.track("refund_requested", { email, pincode });
  await Refund.create({ email, phone_number, home_address, pincode });
  res.sendStatus(202);
}

module.exports = { refund };
