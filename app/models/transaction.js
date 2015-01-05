import DS from 'ember-data';
var attr = DS.attr;
var belongsTo = DS.belongsTo;

export default DS.Model.extend({
  amount: attr(),
  createdAt: attr(),
  receiver: belongsTo('account'),
  sender: belongsTo('account'),
  signature: attr()
});
