const crypto = require("node:crypto");

const generateApiKey = () => `sk_${crypto.randomBytes(32).toString("hex")}`;

module.exports = {
  generateApiKey
};
