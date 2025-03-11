import mongoose from "mongoose";

function connect() {
    mongoose.connect(process.env.MONGODB_URI)
     .then(() => {
         console.log("Successfully connected to the database")
     })
     .catch(err => {
        console.log(err);
})
}

    export default connect;