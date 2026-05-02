const crypto = require("node:crypto");

module.exports = () => crypto.randomInt(100000, 999999).toString();