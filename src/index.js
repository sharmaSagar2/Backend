import dotevn from "dotenv";
import {connectDB} from "./db/index.js"


dotevn.config({
    path:'./env'
})

connectDB()
.then(()=>{
    app.listen(process.env.PORT || 8000, ()=>{
        console.log(`server is running at port: ${process.env.PORT}`)
    })
})
.catch((err)=>{
    console.log("MONGDB connection failed !!!",err)
})

