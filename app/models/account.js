import DS from 'ember-data';
var attr = DS.attr;

export default DS.Model.extend({
  primaryKey: 'address',
  address: attr(),
  public_key: attr(),
  private_key: function(){
    return localStorage[this.get('public_key')]
  }.property(),
  locked: function(){
    return typeof this.get('private_key') === 'undefined'
  }.property('private_key'),
  wallet_key: function(){
    var canvas = blockies.create({
      seed: this.get('private_key'),
    })

    var context = canvas.getContext("2d");
    context.globalAlpha = 0.60;
    context.fillStyle = "#74B63E";
    context.font = "32px 'Open Sans' Helvetica";
    context.fillText('&', 15, 39);
    context.fill();

    return steganography.encode(this.get('private_key'), canvas.toDataURL('image/png'))
  }.property('private_key')
});
