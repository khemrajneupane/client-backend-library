import express from 'express'

import { checkJwt } from '../middlewares/checkJwt'
import { createUserValidate } from '../middlewares/validateSignup'

import {
  createUser,
  findAll,
  findById,
  updateUser,
  deleteUser,
} from '../controllers/user'

const router = express.Router()
router.post('/', createUserValidate, createUser)
router.get('/', findAll)
router.get('/:userId', findById)
router.put('/:userId', updateUser)
router.delete('/:userId', checkJwt, deleteUser)
export default router
