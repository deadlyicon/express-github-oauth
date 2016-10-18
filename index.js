const randomstring = require('randomstring')
const URL = require('url')
const Request = require('request-promise')
const querystring = require('querystring')

const GithubOauth = {
  CLIENT_ID: process.env.GITHUB_CLIENT_ID,
  CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
  callbackProtocol: process.env.NODE_ENV === 'production' ? 'https' : 'http',
  callbackPath: '/github_oauth_callback',
  scope: 'user:email',
  allow_signup: 'true',

  oauthRedirectURI(request){
    return URL.format({
      protocol: GithubOauth.callbackProtocol || 'http',
      host: request.get('host'),
      pathname: GithubOauth.callbackPath,
    })
  },

  authorizeURL(request, response){
    const state = randomstring.generate()
    request.session.oauth_state = state

    const url = URL.parse('https://github.com/login/oauth/authorize')
    url.query = {
      client_id: GithubOauth.CLIENT_ID,
      redirect_uri: GithubOauth.oauthRedirectURI(request),
      state: state,
      scope: GithubOauth.scope,
      allow_signup: GithubOauth.allow_signup,
    }
    return URL.format(url)
  },

  authorize(request){
    if (request.query.state !== request.session.oauth_state){
      const error = new Error('LOGIN FAILED')
      error.status = 400
      return Promise.reject(error)
    }

    return GithubOauth.requestAccessToken(request)
      .then(results => {
        results = querystring.parse(results)
        request.session.github_access_token = results.access_token
        request.session.github_scope = results.scope
        request.session.github_token_type = results.token_type
        return GithubOauth.requestUserProfile(request)
      })
      .catch(error => {
        error.status = 500
        throw error;
      })
  },

  githubAccessTokenURL(request){
    const url = URL.parse('https://github.com/login/oauth/access_token')
    url.query = {
      client_id: GithubOauth.CLIENT_ID,
      client_secret: GithubOauth.CLIENT_SECRET,
      code: request.query.code,
      redirect_uri: GithubOauth.oauthRedirectURI(request),
      state: request.session.oauth_state,
    }
    return URL.format(url)
  },

  requestAccessToken(request){
    return Request.post(GithubOauth.githubAccessTokenURL(request))
  },

  requestUserProfile(request){
    return Request({
      json: true,
      method: 'GET',
      url: 'https://api.github.com/user',
      headers: {
        'Authorization': `token ${request.session.github_access_token}`,
        'User-Agent': 'node',
      },
    })
  },

  ensureConfigured(){
    if (!GithubOauth.CLIENT_ID) throw new Error('GitHub CLIENT_ID undefined')
    if (!GithubOauth.CLIENT_SECRET) throw new Error('GitHub CLIENT_SECRET undefined')
  },

  redirectToLoginViaGithub(request, response){
    GithubOauth.ensureConfigured()
    request.session.redirectToAfterLogin = request.header('Referer')
    response.redirect(GithubOauth.authorizeURL(request))
  },

  oauthCallbackHanler(findOrCreateUser){
    return (request, response, next) => {
      GithubOauth.ensureConfigured()
      GithubOauth.authorize(request)
        .then(findOrCreateUser)
        .then(currentUser => {
          request.session.userId = currentUser.id
          response.redirect(request.session.redirectToAfterLogin || '/')
          delete request.session.redirectToAfterLogin
        })
        .catch(next)
    }
  }

}

module.exports = GithubOauth
