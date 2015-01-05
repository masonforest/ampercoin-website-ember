import Ember from 'ember';

export function formatAddress(address) {
  if(address) {
    return '&' + address;
  } else {
    return 'Anonymous'
  }
};

export default Ember.Handlebars.makeBoundHelper(formatAddress);
