import Ember from 'ember';

export default Ember.Controller.extend({
  transactions: function() {

    return Ember.ArrayProxy.createWithMixins(Ember.SortableMixin, {
      sortProperties: ['createdAt'],
      sortAscending: false,
      content: this.model.get('transactions')
    });
  }.property('transactions'),
  actions: {
    comingSoon: function() {
      alert('Coming Q4 2015')
    },
    createTransaction: function() {
      var store = this.get('store')
      var contract = {
        sender_id: this.model.get('id'),
        receiver_id: this.model.get('id'),
        amount: this.get('amount'),
      }

      var signature = this.model.sign(JSON.stringify(contract))
      var transaction = store.createRecord('transaction', {
        receiver: this.model,
        sender: this.model,
        amount: this.get('amount'),
        signature: signature
      });

      var self = this;

      transaction.save().then(function(transaction) {
        //self.model.get('transactions').unShiftObject(transactions)
      });
    }
  }
});
