import DS from 'ember-data';
var attr = DS.attr;

export default DS.Model.extend({
  account: DS.belongsTo('account'),
  address: attr(),
  payment_address: attr(),
  paid: attr(),
  amountInBTC: function() {
    return 0.02
  }.property('amount'),
});
