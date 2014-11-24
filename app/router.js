import Ember from 'ember';
import config from './config/environment';

var Router = Ember.Router.extend({
  location: config.locationType
});

Router.map(function() {
  this.route('learnMore');
  this.resource('orders', { path: '/orders/:order_id' }, function(){
    this.route('show')
  }
  );
});

export default Router;
