import passport from 'passport'
import express from 'express'
import { googleLogin } from '../controllers/login'
const router = express.Router()

router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
)
router.get('/google/callback', passport.authenticate('google'), googleLogin)

export default router
