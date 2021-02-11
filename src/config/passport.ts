import passport from 'passport'
import PassportGoogleStrategy from 'passport-google-oauth20'

import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '../util/secrets'
import UserService from '../services/user'
import User from '../models/User'

const GoogleStrategy = PassportGoogleStrategy.Strategy

passport.serializeUser<any, any>((user, done) => done(undefined, user.id))
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => done(err, user))
})
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3001/api/v1/auth/google/callback',
    },
    async function (accessToken: any, refreshToken: any, profile, done: any) {
      let emailId = '' 
      const photoId = profile._json['picture']
      console.log(profile.id)
      if (profile.emails) {
        emailId = profile.emails[0].value
      }
      const currentUser = await User.findOne({ email: emailId }).exec()
      if (currentUser) {
        done(undefined, currentUser)
      } else {
        const newUser = new User({
          username: profile.name?.givenName,
          email: emailId,
          image: photoId,
          googleId: profile.id,
        }).save()
        done(undefined, newUser)
      }
    }
  )
)
