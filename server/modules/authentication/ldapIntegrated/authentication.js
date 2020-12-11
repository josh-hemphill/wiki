/* global WIKI */

// ------------------------------------
// Local Account
// ------------------------------------

const LocalStrategy = require('passport-local').Strategy

function isIntegerLike(prop) {
	return typeof prop !== 'symbol' && !isNaN(parseInt('' + prop, 10));
}
function isObject(obj) {
	return Object.prototype.toString.call(obj) === '[object Object]';
}
function hasOwnProperty(obj, prop) {
	return Object.prototype.hasOwnProperty.call(obj, prop);
}
function isSafe(obj, prop) {
	if (isObject(obj)) {
		return obj[prop] === undefined || hasOwnProperty(obj, prop);
	}

	if (Array.isArray(obj)) {
		return !isNaN(parseInt('' + prop, 10));
	}

	return false;
}
function getObj(obj, path) {
  const segs = path.split('.');
  const attr = segs.pop();
  let currentLayer = obj;

  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    if (isSafe(currentLayer, seg)){
      if (Array.isArray(currentLayer) && isIntegerLike(seg)) {
        currentLayer = currentLayer[seg];
      } else {
        const overCurrent = currentLayer;
        currentLayer = overCurrent[seg];
      }
    } else {
      return;
    }
  }
  if (attr !== null && attr !== undefined) {
    if (Array.isArray(currentLayer) && isIntegerLike(attr)) {
      return currentLayer[attr];
    } else if (isObject(currentLayer)) {
      return currentLayer[attr];
    } else {
      return;
    }
  } else {
    return;
  }
}

module.exports = {
  init (passport, conf) {
    passport.use('ldapIntegrated',
      new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
      }, async (uEmail, uPassword, done) => {
        try {
          const user = await WIKI.models.users.query().findOne({
            email: uEmail.toLowerCase(),
            providerKey: 'local'
          })
          WIKI.logger.warn(JSON.stringify(Object.keys(WIKI)))
          console.debug(getObj(WIKI,uPassword))
          if (user) {
            await user.verifyPassword(uPassword)
            if (!user.isActive) {
              done(new WIKI.Error.AuthAccountBanned(), null)
            } else if (!user.isVerified) {
              done(new WIKI.Error.AuthAccountNotVerified(), null)
            } else {
              done(null, user)
            }
          } else {
            done(new WIKI.Error.AuthLoginFailed(), null)
          }
        } catch (err) {
          done(err, null)
        }
      })
    )
  }
}
