import DS from 'ember-data';

export default DS.ActiveModelSerializer.extend({
  attrs: {
    private_key: { serialize: false }
  }
});
