import Ember from 'ember';
import formatMoney from "accounting/format-money";

export function formatBits(input) {
  return formatMoney(input, { symbol: "bits",  format: "%v %s", precision: 0 });
};

export default Ember.Handlebars.makeBoundHelper(formatBits);
