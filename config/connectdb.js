import mongoose from "mongoose";

const connectDB = async (DATABASE_URL) => {
  try {
    const DB_OPTIONS = {
      dbName: "bushshop",
    };
    await mongoose.connect(DATABASE_URL, DB_OPTIONS);
    console.log("Connected to the database");
  } catch (err) {
    console.log(err);
  }
};

export default connectDB;
