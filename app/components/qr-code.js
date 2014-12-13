import Ember from 'ember';

export default Ember.Component.extend({
  didInsertElement: function() {
    var element = this.get('element');
    new QRCode(element, {
      text: "http://jindo.dev.naver.com/collie",
      width: 168,
      height: 168,
      colorDark : "#000000",
      colorLight : "#ffffff",
      correctLevel : QRCode.CorrectLevel.H
  });
  }
});
