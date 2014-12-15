import DS from 'ember-data';
import config from '../config/environment';

export default DS.RESTAdapter.extend({
  host: config.API_ENDPOINT,
  ajax: function(url, method, hash) {
    if (hash) {
      hash.crossDomain = true;
      hash.xhrFields = {withCredentials: true};
    }

    return this._super(url, method, hash);
  }
});
