import Ember from 'ember';

export default Ember.Component.extend({
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
      this.sendAction(
      {
        amount: this.get('amount')
      }
      )
    }
  }
});
