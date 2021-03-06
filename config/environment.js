/* jshint node: true */

module.exports = function(environment) {
  var ENV = {
    modulePrefix: 'ampercoin-website-ember',
    environment: environment,
    baseURL: '/',
    locationType: 'auto',
    contentSecurityPolicy: {
      'default-src': "'none'",
      'script-src': "'self' 'unsafe-inline' 'unsafe-eval' use.typekit.net connect.facebook.net maps.googleapis.com maps.gstatic.com stats.pusher.com",
      'font-src': "'self' data: fonts.googleapis.com fonts.gstatic.com",
      'connect-src': "'self' www.corsproxy.com ws://ws.pusherapp.com localhost:3000 localhost:4000",
      'img-src': "'self' data: www.facebook.com fonts.googleapis.com",
      'style-src': "'self' 'unsafe-inline' fonts.googleapis.com fonts.gstatic.com",
      'frame-src': "s-static.ak.facebook.com static.ak.facebook.com www.facebook.com"
    },
    EmberENV: {
      FEATURES: {
        // Here you can enable experimental features on an ember canary build
        // e.g. 'with-controller': true
      }
    },

    APP: {
      // Here you can pass flags/options to your application instance
      // when it is created
    }
  };

  ENV.APP.PUSHER_OPTS = { key: 'cacd9c67132726113448', connection: {} }

  if (environment === 'development') {
    // ENV.APP.LOG_RESOLVER = true;
    ENV.API_ENDPOINT = 'http://localhost:3000';
    ENV.AMPERCOIN_API_ENDPOINT = 'http://localhost:4000';
    ENV.APP.LOG_ACTIVE_GENERATION = true;
    // ENV.APP.LOG_TRANSITIONS = true;
    // ENV.APP.LOG_TRANSITIONS_INTERNAL = true;
    ENV.APP.LOG_VIEW_LOOKUPS = true;
  }

  if (environment === 'test') {
    // Testem prefers this...
    ENV.baseURL = '/';
    ENV.locationType = 'auto';

    // keep test console output quieter
    ENV.APP.LOG_ACTIVE_GENERATION = false;
    ENV.APP.LOG_VIEW_LOOKUPS = false;

    ENV.APP.rootElement = '#ember-testing';
  }

  if (environment === 'production') {
    ENV.API_ENDPOINT = 'https://ampercoin-website-api.herokuapp.com';
    ENV.AMPERCOIN_API_ENDPOINT = 'https://node.ampercoin.com';
  }

  return ENV;
};
