const cloudinary = require("cloudinary").v2; // Use v2 explicitly
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// Upload images controller
exports.uploadImages = async (req, res) => {
  try {
    const { path } = req.body;
    let files = Object.values(req.files).flat();
    let images = [];

    for (const file of files) {
      const url = await uploadToCloudinary(file, path);
      images.push(url);
    }
    res.json(images);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

// List images controller
exports.listImages = async (req, res) => {
  const { path, sort, max } = req.body;

  cloudinary.search
    .expression(`${path}`)
    .sort_by("created_at", `${sort}`)
    .max_results(max)
    .execute()
    .then((result) => {
      res.json(result);
    })
    .catch((err) => {
      console.log(err.error.message);
    });
};

// Upload to Cloudinary using buffer
const uploadToCloudinary = async (file, path) => {
  return new Promise((resolve, reject) => {
    // Create a stream to upload the buffer directly
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: path,
      },
      (error, result) => {
        if (error) {
          reject(new Error("Upload image failed."));
        } else {
          resolve({
            url: result.secure_url,
          });
        }
      }
    );

    // Pipe the file buffer to the upload stream
    const bufferStream = require("stream").PassThrough();
    bufferStream.end(file.data); // file.data is the buffer from express-fileupload
    bufferStream.pipe(uploadStream);
  });
};
