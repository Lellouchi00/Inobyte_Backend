const geoip = require("geoip-lite");

const getLocationFromIp = (ip) => {
  if (!ip) return null;

  const geo = geoip.lookup(ip);
  if (!geo) return null;

  return [geo.city, geo.country].filter(Boolean).join(", ") || geo.country || null;
};

const getCountryFromLocation = (location) => {
  if (!location) return null;
  const parts = String(location).split(",").map((part) => part.trim()).filter(Boolean);
  return parts[parts.length - 1] || null;
};

module.exports = {
  getCountryFromLocation,
  getLocationFromIp
};
