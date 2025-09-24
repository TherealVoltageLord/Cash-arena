exports.validateAmount = (amount, min, max) => {
  return amount >= min && amount <= max;
};

exports.validatePassword = (password) => {
  return password.length >= 6;
};

exports.calculateROI = (amount, tier) => {
  const rates = { Bronze: 0.5, Silver: 1.5, Gold: 2.5 };
  return (amount * rates[tier]) / 100;
};