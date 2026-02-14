require('dotenv').config()
const express = require('express')
const cors = require("cors");
const connectDB = require('./config/db')

//-----------------Routes------------------
const AuthRouter = require('./routes/auth.routes')
const app = express()


// Connect DB
connectDB();

const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(cors());
app.use(express.json());


app.get("/api/test", (req, res) => {
//   res.set('Cache-Control', 'no-store');
  res.status(200).json({
    message: "Backend connected successfully 🚀"
  });
});

app.use('/api/auth', AuthRouter)


const PORT = process.env.PORT || 5000


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));