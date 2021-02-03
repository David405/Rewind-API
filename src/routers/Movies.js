const express = require("express");
const router = express.Router();
const fs = require("fs");
const multer = require("multer");
const _ = require("lodash");
require('express-async-errors');

const auth = require('../middleware/auth')
const Movie = require("../Model/MoviesModel");
const User = require('../Model/UserModel');
const cloud = require("../helpers/cloudinary");
const upload = multer({ dest: "./src/files" });
/* Create Movie */
router.post("/upload", upload.any(), async(req, res, next) => {
  var data = {
    coverpics_url: req.files[0].path,
    movie_url: req.files[1].path,
    title: req.body.title,
    description: req.body.description,
    release_date: req.body.release_date,
    cast: req.body.cast,
    timestamps: Date.now()
  };

  console.log(data);

  try {
  await cloud.uploads(data.coverpics_url).then((img_metadata) => {
      data.coverpics_url = img_metadata.secure_url;
      cloud.uploads(data.movie_url).then((vid_metadata) => {
        data.movie_url = vid_metadata.secure_url;
        console.log(data);

        var movie = Movie.create(data)
            return res.json({
              success: true,
              message: data,
            });
        });
      });
  } catch (error) {
    return res.json({
      success: false,
      message: error,
    });
  }
});

/* Edit A Movie Entry*/
router.post("/edit/:id",  async(req, res, next) => {
  data = {
    title: req.body.title,
    description: req.body.description,
    release_date: req.body.release_date,
    cast: req.body.cast,
    timestamps: Date.now(),
  };

  var movie = await Movie.findByIdAndUpdate({ _id: req.params.id }, data) 
      return res.send({
        success: true,
        message: movie,
      });
});

/* Get All Movies */
router.get("/", async(req, res, next) => {
  var movie = await Movie.find({})
      return res.send({
        success: true,
        message: movie,
      });
});

/* Get A Movie */
router.get("/:id", async(req, res, next) => {
  var movie = await Movie.find({ _id: req.params.id })
  if(!movie){
    return res.send({
      success: false,
      message: "Movie not found"
    })
  } else {
      return res.send({
        success: true,
        message: movie,
      });
  }
});

/* Delete Movie */
router.delete("/delete/:id", async(req, res, next) => {
 var movie = await Movie.findOneAndDelete({ _id: req.params.id })
      return res.send({
        success: true,
        message: movie,
      });
});

/* Search Movie */
router.get("/search/movie", async(req, res, next) => {
  var data = new RegExp(req.query.q, 'gi');

  try {  
  var movies = await Movie.find({$text: {$search: data}});  
  //check if movie is not found 
    if(_.isEmpty(movies)){
      return res.send({
        success: false,
        message: "Movie not found"
      })
    }
       return res.send({
         success: true,
         message: movies
       }) 
      
    } catch (error){
    return res.send({
      success: false,
      message: error
    })
  }
})

module.exports = router;
