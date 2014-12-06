import Ember from 'ember';
import formatMoney from "accounting/format-money";

export function bitsToUsd(input) {
  return "about " + formatMoney(input * 377.75) + " USD";
};

export default Ember.Handlebars.makeBoundHelper(bitsToUsd);
