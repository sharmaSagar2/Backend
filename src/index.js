import dotevn from "dotenv";
import {connectDB} from "./db/index.js"


dotevn.config({
    path:'./env'
})

connectDB();

