import Ember from 'ember';
import formatMoney from "accounting/format-money";

export function bitsToUsd(input) {
  return "about " + formatMoney(input * 0.00037775) + " USD";
};

export default Ember.Handlebars.makeBoundHelper(bitsToUsd);
