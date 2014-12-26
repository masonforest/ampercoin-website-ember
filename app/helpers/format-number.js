import Ember from 'ember';

export function formatNumber(input) {
  if(input) {
    return input.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }
};

export default Ember.Handlebars.makeBoundHelper(formatNumber);
