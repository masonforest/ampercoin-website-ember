import Ember from 'ember';

export default Ember.Controller.extend({
  ready: function () {
    $('[data-toggle="tooltip"]').tooltip()
  },
  subtotal: function(){
    if(this.get('amount')) {
      return (this.get('amount') * 2000);
    } else {
      return 0;
    }
  }.property('amount'),
  total: function() {
    if(this.get('subtotal')) {
      return this.get('subtotal') + 20000;
    } else {
      return 20000;
    }
    }.property('subtotal'),
  actions: {
    createOrder: function() {
      var store = this.get('store')
      var order = store.createRecord('order',
        {
          address: this.get('address'),
          amount: this.get('amount')
        }
      );

      var self = this;

      var onSuccess = function(order) {
        console.log(order)
        self.transitionToRoute('orders', order);
      };

      var onFail = function(order) {
        console.log(order)
        // deal with the failure here
      };

      order.save().then(onSuccess, onFail);
    },
    learnMore: function() {
      $('html, body').animate({
          scrollTop: 600
      }, 1000);
    },
    checkout: function(){
      alert('hi')
      console.log(this.store.all('order'));
    },
  }
});
