import Ember from 'ember';
import formatMoney from "accounting/format-money";

export function formatMoney(input) {
  return formatMoney(input);
}

export default Ember.Handlebars.makeBoundHelper(formatMoney);
