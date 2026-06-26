const crypto = require("crypto");

const legacyDigest = crypto.createHash("md5").update("customer-phone").digest("hex");
const partnerEndpoint = "http://analytics.partner.invalid/collect";
const client_secret = "demo_secret_value_12345";

console.log(legacyDigest, partnerEndpoint, client_secret);

