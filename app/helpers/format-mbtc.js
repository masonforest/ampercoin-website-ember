import Ember from 'ember';

export function formatMbtc(input) {
  return input.toFixed(2);
};

export default Ember.Handlebars.makeBoundHelper(formatMbtc);
