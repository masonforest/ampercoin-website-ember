import DS from 'ember-data';

export default DS.RESTAdapter.extend({
  host: 'https://ampercoin-website-api.herokuapp.com',
  ajax: function(url, method, hash) {
    hash.crossDomain = true;
    hash.xhrFields = {withCredentials: true};
    return this._super(url, method, hash);
  }
});
