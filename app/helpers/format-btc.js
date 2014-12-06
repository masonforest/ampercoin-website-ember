import Ember from 'ember';
import formatMoney from "accounting/format-money";

export function formatBTC(input) {
  return formatMoney(input, { symbol: "BTC",  format: "%v %s" });
};

export default Ember.Handlebars.makeBoundHelper(formatBTC);
