import DS from 'ember-data';
var attr = DS.attr;
var hasMany = DS.hasMany;
var Buffer = buffer.Buffer

export default DS.Model.extend({
  primaryKey: 'address',
  address: attr(),
  balance: attr(),
  publicKey: attr(),
  transactions: hasMany('transaction', {"inverse": null}),
  sign: function(message){
    var privateKey = Buffer(this.get('privateKey'), 'hex')
    var key = new ECKey(privateKey)
    var messageHash = buffer.Buffer(sha256(message), 'hex');
    return buffer.Buffer(ECDSA.serializeSig(ECDSA.sign(messageHash, key.privateKey))).toString('base64')
  },
  privateKey: function(){
    return localStorage[this.get('publicKey')]
  }.property(),
  locked: function(){
    return typeof this.get('privateKey') === 'undefined'
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

    return steganography.encode(this.get('privateKey'), canvas.toDataURL('image/png'))
  }.property('privateKey')
});
