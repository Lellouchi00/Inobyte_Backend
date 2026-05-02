const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

const validateEmail = (email) => {
  if (!email || typeof email !== "string") return "Email is required";
  if (!EMAIL_REGEX.test(email.trim())) return "Invalid email format";
  return null;
};

const validatePassword = (password) => {
  if (!password || typeof password !== "string") return "Password is required";
  if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  return null;
};

module.exports = {
  validateEmail,
  validatePassword
};
