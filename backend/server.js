require('dotenv').config()
const express = require('express')
const cookieParser = require("cookie-parser");
const cors = require("cors");
const connectDB = require('./config/db')

//-----------------Routes------------------
const AuthRouter = require('./routes/auth.routes')
const app = express()


// Connect DB
connectDB();

// CORS first
app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true
}));
app.use(cookieParser());
// prevent browser caching
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

app.use(express.json());

app.use('/api/auth', AuthRouter)


const PORT = process.env.PORT || 5000


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));