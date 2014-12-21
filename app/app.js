import Ember from 'ember';
import Resolver from 'ember/resolver';
import loadInitializers from 'ember/load-initializers';
import config from './config/environment';

Ember.MODEL_FACTORY_INJECTIONS = true;

var App = Ember.Application.extend({
  modulePrefix: config.modulePrefix,
  podModulePrefix: config.podModulePrefix,
  Resolver: Resolver,
  ApplicationSerializer: DS.ActiveModelSerializer
});

// $.ajax(
//   {
//     url: 'http://jsbox-runner.herokuapp.com/masonforest/btc_to_usd',
//    data: {btc: 1},
//    method: 'POST',
//    success: function(d){
//       alert(d);
//    }
//   }
// );

loadInitializers(App, config.modulePrefix);

export default App;
