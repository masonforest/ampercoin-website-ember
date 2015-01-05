import Ember from 'ember';

export default Ember.ObjectController.extend(EmberPusher.Bindings, {
  layoutName: 'layout',
  logPusherEvents: true,
  PUSHER_SUBSCRIPTIONS: {
    payments: ['paid']
  },
  actions: {
    paid: function (order){
      this.transitionToRoute("account", this.model.get("preordered_account.address"));
    }
  }
});
