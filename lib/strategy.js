/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Citrix authentication strategy authenticates requests by delegating to
 * Citrix using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Citrix application's Client ID
 *   - `clientSecret`  your Citrix application's Client Secret
 *   - `callbackURL`   URL to which Citrix will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new CitrixStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/citrix/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.name = options.name || 'citrix';
  options.authorizationURL = options.authorizationURL || 'https://api.citrixonline.com/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://api.citrixonline.com/oauth/access_token';
  options.customHeaders = options.customHeaders || {};

  OAuth2Strategy.call(this, options, verify);
  this.name = options.name;
  this._oauth2.useAuthorizationHeaderforGET(true);


  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    var params= params || {};
    params['client_id'] = this._clientId;
    params['client_secret'] = this._clientSecret;
    var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
    params[codeParam]= code;

    var post_data= querystring.stringify( params );
    var post_headers= {
         'Content-Type': 'application/x-www-form-urlencoded'
     };


    this._request("GET", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
      if( error )  callback(error);
      else {
        var results;
        try {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
          // responses should be in JSON
          results= JSON.parse( data );
        }
        catch(e) {
          // .... However both Facebook + Github currently use rev05 of the spec
          // and neither seem to specify a content-type correctly in their response headers :(
          // clients of these services will suffer a *minor* performance cost of the exception
          // being thrown
          results= querystring.parse( data );
        }
        var access_token= results["access_token"];
        var refresh_token= results["refresh_token"];
        delete results["refresh_token"];
        callback(null, access_token, refresh_token, results); // callback results =-=
      }
    });
  }
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from GitHub.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `citrix`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  setTimeout(function(){
    done(null, {provider: 'citrix'});
  }, 0);
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
