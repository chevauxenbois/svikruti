const express = require("express");
const Razorpay = require("razorpay");
const router = express.Router();

router.post("/checkout", async (req, res) => {
  const {
    full_name,
    email_address,
    mobile_number,
    address_line,
    pincode,
    pan_number,
    upi_id,
  } = req.body;

  console.log("checkout payload", email_address, mobile_number, pan_number);

  await db.orders.insert({
    full_name,
    email_address,
    mobile_number,
    address_line,
    pincode,
    pan_number,
    upi_id,
  });

  return res.json({ ok: true });
});

module.exports = router;
