import Ember from 'ember';

export default Ember.Controller.extend(EmberPusher.Bindings, {
  //layoutName: 'layout',
  logPusherEvents: true,
  PUSHER_SUBSCRIPTIONS: {
    myChannel: ['my-event']
  },
  subtotal: function(){
    if(this.get('amount')) {
      return BigNumber(this.get('amount')).times(0.002).toFixed(3);
    } else {
      return 0;
    }
  }.property('amount'),
  total: function() {
    if(this.get('subtotal')) {
      return BigNumber(this.get('subtotal')).plus(0.02).toFixed(3);
    } else {
      return (0.020).toFixed(3);
    }
    }.property('subtotal'),
  actions: {
    createOrder: function() {
      var store = this.get('store')
      var randomBytes = secureRandom(32);
      var key = new ECKey(randomBytes, true);

      localStorage[key.publicKey.toString('hex')] = key.privateKey.toString('hex')
      var account = store.createRecord('account', {
        address: this.get('address'),
        public_key: key.publicKey.toString('hex'),
      })
      var self = this;

      account.save().then(function(account) {
        var order = store.createRecord('order');
        order.set('account', account)

        var onSuccess = function(order) {
          self.transitionToRoute("order", order);
        };

        var onFail = function(order) {
          console.log(order)
          // deal with the failure here
        };

        order.save().then(onSuccess, onFail);
      });

      // var self = this;
      //
    }
    },
    init: function(){
      this._super();
      self = this;
      $.getJSON('http://localhost:3000/accounts').then(function(data){
        self.set('accounts_remaining', data.meta.accounts_remaining);
      },function(e,a){console.log(a)});
  }
});
