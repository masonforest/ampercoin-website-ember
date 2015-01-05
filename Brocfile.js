/* global require, module */

var EmberApp = require('ember-cli/lib/broccoli/ember-app');

var app = new EmberApp({
  vendorFiles:{
    'handlebars.js':{
      production: 'bower_components/handlebars/handlebars.min.js'
    }
  }
});

app.import('bower_components/moment/moment.js')
app.import('bower_components/buffer/buffer.js')
app.import('bower_components/steganography/src/steganography.js')
app.import('bower_components/blockies/blockies.js')
app.import('bower_components/qrcodejs/qrcode.js')
app.import('bower_components/bignumber.js/bignumber.js')
app.import('bower_components/pusher/dist/pusher.js')
app.import('bower_components/secure-random/lib/secure-random.js')
app.import('vendor/ember-pusher/ember-pusher.js')
app.import('vendor/sha256/sha256.js')
app.import('vendor/eckey/ECKey.js')
app.import('vendor/ecdsa/ECDSA.js')

// Use `app.import` to add additional libraries to the generated
// output files.
//
// If you need to use different assets in different
// environments, specify an object as the first parameter. That
// object's keys should be the environment name and the values
// should be the asset to use in that environment.
//
// If the library that you are including contains AMD or ES6
// modules that you would like to import into your application
// please specify an object with the list of modules as keys
// along with the exports of each module as its value.

module.exports = app.toTree();
