import Ember from 'ember';
import config from './config/environment';

var Router = Ember.Router.extend({
  location: config.locationType
});

Router.map(function() {
  this.route('learnMore');
  this.resource('order', { path: '/orders/:order_id' });
  this.resource('account', { path: ':address' });
});

export default Router;
