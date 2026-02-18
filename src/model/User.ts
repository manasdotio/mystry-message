import mongoose, { Schema, Document } from "mongoose";

export interface Message extends Document {
  // extends Document to include Mongoose document properties
  content: string;
  createdAt: Date;
}

const MessageSchema: Schema<Message> = new Schema({
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

// User interface extends Document to include Mongoose document properties
export interface User extends Document {
  username: string;
  email: string;
  password: string;
  verifyCode: string;
  verifyCodeExpiry: Date;
  isVerified: boolean;
  isAcceptingMessage: boolean;
  Messages: Message[]; // Array of Message subdocuments
}

const UserSchema: Schema<User> = new Schema({
  username: {
    type: String,
    required: [true, "Username is required"],
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    match: [/\S+@\S+\.\S+/, "Please use a valid email address"],
  },
  password: {
    type: String,
    required: true,
  },
  verifyCode: {
    type: String,
    required: [true, "Verify code is required"],
  },
  verifyCodeExpiry: {
    type: Date,
    required: [true, "Verify code expiry is required"],
  },
  isVerified: {
    type: Boolean,
    required: [true, "Verify code expiry is required"],
    default: false,
  },
  isAcceptingMessage: {
    type: Boolean,
    default: true,
  },
  Messages: [MessageSchema], // Embed Message subdocuments
});

const UserModel =
  (mongoose.models.User as mongoose.Model<User>) ||
  mongoose.model<User>("User", UserSchema); // Use existing model if it exists, otherwise create a new one

export default UserModel;
