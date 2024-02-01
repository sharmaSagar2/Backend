import {v2 as cloudinary} from 'cloudinary';
import fs from "fs"
          
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUDE_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if(!localFilePath) return null;
        //upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath,{
            resource_type: "auto"
        })
        //file has been uploaded successfully
       // console.log('file has been uploaded on cloudinary',response.url);
       fs.unlinkSync(localFilePath)
        return response;
        
    } catch (error) {
        fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the operation got failed
        return null; 
    }   
}
const deleteFromCloudinary = async(id) => {
    try {
        const response = await cloudinary.uploader.destroy(id)
        return response
    } catch (error) {
        console.error('Error deleting image from Cloudinary:', error);
        return null;
    }
}

export {uploadOnCloudinary,deleteFromCloudinary}