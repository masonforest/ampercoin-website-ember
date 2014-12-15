import DS from 'ember-data';
var attr = DS.attr;

export default DS.Model.extend({
  address: attr(),
  payment_address: attr(),
  paid: attr(),
  amountInBTC: function() {
    return 0.02
  }.property('amount'),
  bitcoinAddress: function() {
    return '18WtEEyNbv7Ldst7XpbQxK37wnfwdf3Z7b';
  }.property()
});
