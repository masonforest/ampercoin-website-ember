import Ember from 'ember';

export default Ember.Controller.extend({
  logPusherEvents: true,
  PUSHER_SUBSCRIPTIONS: {
    myChannel: ['my-event']
  },
  setupController: function(){
    alert('hi')
  }
});
