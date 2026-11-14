// EMI repayment checkout. Card data never touches this service: Razorpay hosts the form.
const express = require("express");
const Razorpay = require("razorpay");
const { Repayment } = require("./models");

const router = express.Router();
const razorpay = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });

router.post("/repayments", async (req, res) => {
  const { email, phone_number, upi_id, amount } = req.body;
  const order = await razorpay.orders.create({ amount, currency: "INR", notes: { email, phone_number } });
  await Repayment.create({ email, phone_number, upi_id, razorpay_order: order.id, amount });
  console.log("repayment order created", order.id);
  res.json({ order_id: order.id });
});

module.exports = router;
