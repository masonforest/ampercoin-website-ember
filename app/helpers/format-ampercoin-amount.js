import Ember from 'ember';

export function formatAmpercoinAmount(amount) {
  if (amount) {
    return parseFloat(amount).toFixed(2);
  } else {
    return "0.00"
  }
};

export default Ember.Handlebars.makeBoundHelper(formatAmpercoinAmount);
