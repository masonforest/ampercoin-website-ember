import DS from 'ember-data';
var attr = DS.attr;

export default DS.Model.extend({
  address: attr(),
  public_key: attr(),
});
