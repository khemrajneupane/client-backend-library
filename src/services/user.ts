import bcrypt from 'bcrypt-nodejs'

import User, { UserDocument } from '../models/User'

function create(user: UserDocument): Promise<UserDocument> {
  return user.save()
}

function findAll(): Promise<UserDocument[]> {
  return User.find().select({ password: false }).populate('loan').exec() // Return a Promise
}

function findById(userId: string): Promise<UserDocument> {
  return User.findById(userId)
    .exec()
    .then((user) => {
      if (!user) {
        throw new Error(`User ${userId} not found`)
      }
      return user
    })
}

//Find by email
function findByEmail(email: string): Promise<UserDocument | null> {
  const user = User.findOne({ email: email }).exec()
  return user
}

function update(
  userId: string,
  update: Partial<UserDocument>
): Promise<UserDocument> {
  return User.findById(userId)
    .exec()
    .then((user) => {
      if (!user) {
        throw new Error(`User ${userId} not found`)
      }
      if (update.username) {
        user.username = update.username
      }
      if (update.email) {
        user.email = update.email
      }
      if (update.isAdmin) {
        user.isAdmin = update.isAdmin
      }
      if (update.joinedDate) {
        user.joinedDate = update.joinedDate
      }
      if (update.password) {
        user.password = update.password
      }
      return user.save()
    })
}

function deleteUser(userId: string): Promise<UserDocument | null> {
  return User.findByIdAndDelete(userId).exec()
}

//Reset Password
async function resetPass(
  userId: string,
  newResetPassword: string
): Promise<UserDocument | null> {
  const user = await User.findById(userId).exec()
  if (!user) {
    throw new Error(`User ${userId} not found`)
  }
  if (newResetPassword) {
    user.password = newResetPassword
  }
  return user.save()
}
export default {
  create,
  findAll,
  findById,
  update,
  deleteUser,
  findByEmail,
  resetPass
}
