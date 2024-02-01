import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary,deleteFromCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from 'jsonwebtoken';
import mongoose from "mongoose";


//Function to extract public ID from Cloudinary URL
const getPublicIdFromUrl = (url) => {
   const startIndex = url.lastIndexOf("/") + 1;
   const endIndex = url.lastIndexOf(".");
   return url.substring(startIndex, endIndex);
 }

//generate access and refresh tokens
const generateAccessAndRefreshTokens = async (userId) => {
   try {
      const user = await User.findById(userId)
      const accessToken = user.generateAccessToken()
      const refreshToken =  user.generateRefreshToken()
      user.refreshToken = refreshToken
      await user.save( { validateBeforeSave: false } )
      return { accessToken, refreshToken}
      
   } catch (error) {
      throw new ApiError(500,"something went wrong while generating access and refersh token")
      
   }
}
//register user
const registerUser = asyncHandler( async (req,res) => {
    //get user detail from frontend
    //validation - not empty
    //check if user already exists:check using username,email
    //check for images , check for avtar
    //upload them to cloudinary,avatar(check uploaded or not)
    //create user object-creation entry in db
    //remove password and refresh token field from response
    //check for user creation 
    //return response
    const {fullName, email, username, password} = req.body 
    if(
        [fullName, email, username, password].some( (field) => field?.trim() === "")
        ) {
            throw new ApiError(400,"All fields are required")
           }
        
           const existedUser = await User.findOne({
                $or: [ { username }, { email } ]
           })

           if(existedUser) {
            throw new ApiError(409,"User with email or username already exists")
           }
           //these are also correct
         //const avatarLocalPath = req.files && req.files.avatar && req.files.avatar[0] && req.files.avatar[0].path;
         //const coverImageLocalPath = req.files && req.files.coverImage && req.files.coverImage[0] && req.files.coverImage[0].path;
         // let coverImageLocalPath;
         // if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
         //     coverImageLocalPath = req.files.coverImage[0].path
         // }
          const avatarLocalPath = req.files?.avatar[0]?.path;
          const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

          if(!avatarLocalPath) {
            throw new ApiError(400,"avatar file is required")
          }


         const avatar = await uploadOnCloudinary(avatarLocalPath);
         const coverImage = await uploadOnCloudinary(coverImageLocalPath)

         if(!avatar) {
            throw new ApiError(400,"avatar file is required")
         }

         const user = await User.create({
            fullName,
            avatar: avatar.url,
            coverImage: coverImage?.url || "",
            email,
            password,
            username:username.toLowerCase(),
         })
         
         const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
         )

         if(!createdUser) {
            throw new ApiError(500,"something went wrong while registering a user")
         }

         return res.status(201).json(
            new ApiResponse(200,createdUser,"User registered successfully")
         )



})

//login user
const loginUser = asyncHandler( async (req,res) => {
   //req body -> data
   //username or email
   //find the user
   //check password
   //access and referesh token
   //send in cookies
   const  {email,username,password } = req.body;

   if(!(username || email)) {
      throw new ApiError(400,"username or email is required")
   }

  const user =  await User.findOne({
      $or: [ { username }, { email } ]
   })

   if(!user) {
      throw new ApiError(404,"user does not exists")
   }

   const isPasswordVaild = await  user.isPasswordCorrect(password)
   if(!isPasswordVaild) {
      throw new ApiError(401,"Invalid user credentials")
   }

   const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

   const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

   const options = {
      httpOnly: true,
      secure: true
   }

   return res
   .status(200)
   .cookie("accessToken",accessToken,options)
   .cookie("refreshToken",refreshToken.options)
   .json(
      new ApiResponse(
         200,
         {
            user: loggedInUser, accessToken, refreshToken 
         },
         "User loggedIn Successfully"
      )
   )


})

//logout user
const logoutUser = asyncHandler( async (req,res) => {
   await User.findByIdAndUpdate(
      req.user._id,
      {
         $unset: {
            refreshToken: 1
         }
      },
      {
         new: true
      }

   )
   const options = {
      httpOnly: true,
      secure: true
   }
   return res
   .status(200)
   .clearCookie("accessToken",options)
   .clearCookie("refreshToken",options)
   .json(new ApiResponse(200,{},"User logged Out"))
})

//refresh access token -> need to figure out
const refreshAccessToken = asyncHandler(async (req, res) => {

   const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken || req.body.refreshToken || req.query.refreshToken

   if (!incomingRefreshToken) {
       throw new ApiError(401, "unauthorized request")
   }

   try {
       const decodedToken = jwt.verify(
           incomingRefreshToken,
           process.env.REFRESH_TOKEN_SECRET
       )
   
       const user = await User.findById(decodedToken?._id)
   
       if (!user) {
           throw new ApiError(401, "Invalid refresh token")
       }
   
       if (incomingRefreshToken !== user?.refreshToken) {
           throw new ApiError(401, "Refresh token is expired or used")
           
       }
   
       const options = {
           httpOnly: true,
           secure: true
       }
   
       const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
   
       return res
       .status(200)
       .cookie("accessToken", accessToken, options)
       .cookie("refreshToken", newRefreshToken, options)
       .json(
           new ApiResponse(
               200, 
               {accessToken, refreshToken: newRefreshToken},
               "Access token refreshed"
           )
       )
   } catch (error) {
       throw new ApiError(401, error?.message || "Invalid refresh token")
   }

})

//change current password
const changeCurrentPassword = asyncHandler(async(req, res) => {
   const {oldPassword, newPassword} = req.body

   const user = await User.findById(req.user?._id)
   const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

   if (!isPasswordCorrect) {
       throw new ApiError(400, "Invalid old password")
   }

   user.password = newPassword
   await user.save({validateBeforeSave: false})

   return res
   .status(200)
   .json(new ApiResponse(200, {}, "Password changed successfully"))
})

//get current user
const getCurrentUser = asyncHandler(async(req, res) => {
   return res
   .status(200)
   .json(new ApiResponse(
       200,
       req.user,
       "User fetched successfully"
   ))
})

//update Account Details
const updateAccountDetails = asyncHandler(async(req,res)=>{
   const {fullName,email} = req.body

   if(!(fullName || email)) {
      throw new ApiError(400,"all fields are required")
   }

  const user = await User.findByIdAndUpdate( 
   req.user?._id,
   {
      $set: {
         fullName: fullName,
         email: email
      }
   },
   {new: true}

   ).select("-password")

   return res
   .status(200)
   .json(new ApiResponse(200,user,"account details updated successfully"))
})

//update user avatar and delete existing avatar
const updateUserAvatar = asyncHandler(async (req, res) => {
   const avatarLocalPath = req.file?.path;
 
   if (!avatarLocalPath) {
     throw new ApiError(400, "Avatar file is missing");
   }
 
   try {
     const avatar = await uploadOnCloudinary(avatarLocalPath);
 
     if (!avatar.url) {
       throw new ApiError(400, "Error while uploading avatar file");
     }

     if (req.user.avatar) {
       await deleteFromCloudinary(getPublicIdFromUrl(req.user.avatar));
     }
     const user = await User.findByIdAndUpdate(
       req.user?._id,
       {
         $set: {
           avatar: avatar.url,
         },
       },
       { new: true }
     ).select("-password");
 
     return res
       .status(200)
       .json(new ApiResponse(200, user, "Successfully updated avatar file"));
   } catch (error) {
     console.error("Error updating avatar:", error);
     throw new ApiError(500, "Internal Server Error");
   }
 });
 
//update user cover imge
const updateUserCoverImage = asyncHandler(async(req,res)=>{
   const coverImageLocalPath = req.file?.path
   if(!coverImageLocalPath) {
      throw new ApiError(400,"Cover Image is missing")
   }
   
   const coverImage = await uploadOnCloudinary(coverImageLocalPath)

   if(!coverImage.url) {
      throw new ApiError(400,"Error while uploading cover image file")
   }

   //delete the existing cover image
   if (req.user.coverImage) {
      await deleteFromCloudinary(getPublicIdFromUrl(req.user.coverImage));
    }

   const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
         $set:{
            coverImage:coverImage.url
         }
      },
      {new: true}
   ).select("-password")

   return res
  .status(200)
  .json(new ApiResponse(200,user,"Successfully updated cover image file"))
})

//subscriber Count, subscribedTo
const getUserChannelProfile = asyncHandler(async(req,res) => {
   const {username} = req.params
   if(!username?.trim()) {
      throw new ApiError(400,"username is missing")
   }

   const channel = await User.aggregate([
      {
         $match: {
            username:username?.toLowerCase()
         }
      },
      {
         $lookup:{
            from: "Subscription",
            localField:"_id",
            foreignField:"channel",
            as:"subscribers"
         }
      },
      {
         $lookup:{
            from: "Subscription",
            localField:"_id",
            foreignField:"subscriber",
            as:"subscribedTo"

         }
      },
      {
         $addFields:{
            subscriberCount: {
              $size: "$subscribers" 
            },
            channelsSubscribedToCount: {
               $size:"$subscribedTo"
            },
            isSubscribed: {
               $cond: {
                  if: {$in: [req.user?._id,"$subscribers.subscriber"]},
                  then: true,
                  else: false
               }
            },
         }
      },
      {
         $project: {
            fullName: 1,
            username: 1,
            subscriberCount: 1,
            isSubscribed: 1,
            avatar: 1,
            coverImage: 1,
            email: 1
         }
      },
   ])
   if(!channel?.length) {
      throw new ApiError(404,"channel does not exists")
   }

   return res
   .status(200)
   .json(
      new ApiResponse(200,channel[0],"User channel fetched successfully")
   )

})

//get watch history
const getUserWatchHistory  = asyncHandler(async(req, res) => {
   const user = await User.aggregate([
       {
           $match: {
               _id: new mongoose.Types.ObjectId(req.user._id)
           }
       },
       {
           $lookup: {
               from: "videos",
               localField: "watchHistory",
               foreignField: "_id",
               as: "watchHistory",
               pipeline: [
                   {
                       $lookup: {
                           from: "users",
                           localField: "owner",
                           foreignField: "_id",
                           as: "owner",
                           pipeline: [
                               {
                                   $project: {
                                       fullName: 1,
                                       username: 1,
                                       avatar: 1
                                   }
                               }
                           ]
                       }
                   },
                   {
                       $addFields:{
                           owner:{
                               $first: "$owner"
                           }
                       }
                   }
               ]
           }
       }
   ])

   return res
   .status(200)
   .json(
       new ApiResponse(
           200,
           user[0].watchHistory,
           "Watch history fetched successfully"
       )
   )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getUserWatchHistory 
}