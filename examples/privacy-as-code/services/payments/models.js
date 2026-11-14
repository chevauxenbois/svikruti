const { DataTypes } = require("sequelize");
const sequelize = require("../db");

const Repayment = sequelize.define("Repayment", {
  email: DataTypes.STRING,
  phone_number: DataTypes.STRING,
  upi_id: DataTypes.STRING,
  razorpay_order: DataTypes.STRING,
  amount: DataTypes.INTEGER,
});

module.exports = { Repayment };
