import DS from 'ember-data';
var attr = DS.attr;

export default DS.Model.extend({
  amount: attr(),
  address: attr(),
  paid: attr(),
  amountInBTC: function() {
    return this.get('amount') * .002 + .02
  }.property('amount'),
  bitcoinAddress: function() {
    return '18WtEEyNbv7Ldst7XpbQxK37wnfwdf3Z7b';
  }.property()
});
