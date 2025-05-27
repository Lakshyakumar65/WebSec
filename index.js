const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
var app = express();

app.set('view engine', 'ejs');
 
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());


const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const JWT_EXPIRES_IN = '24h'; // Token expires in 24 hours

const mongoose = require("mongoose");
mongoose.connect("mongodb+srv://eng22cy0053:kSNNjT0zHq3SZpb2@cluster1.mfphlgv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1");


const userSchema = new mongoose.Schema({
   name: {
     type: String,
     required: true,
     trim: true,
     minlength: 2,
     maxlength: 50
   },
   email: {
     type: String,
     required: true,
     unique: true,
     lowercase: true,
     validate: [validator.isEmail, 'Please provide a valid email']
   },
   password: {
     type: String,
     required: true,
     minlength: 6
   },
   createdAt: {
     type: Date,
     default: Date.now
   }
});


userSchema.pre('save', async function(next) {

  if (!this.isModified('password')) return next();
  
  try {
    
    const hashedPassword = await bcrypt.hash(this.password, 12);
    this.password = hashedPassword;
    next();
  } catch (error) {
    next(error);
  }
});


userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);


const secretSchema = new mongoose.Schema({
  content: {
    type: String,
    required: true,
    trim: true
  },
  submittedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  submittedAt: {
    type: Date,
    default: Date.now
  },
  isAnonymous: {
    type: Boolean,
    default: true
  }
});

const Secret = mongoose.model("Secret", secretSchema);

// JWT Token utilities
const signToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const createAndSendToken = (user, statusCode, res, renderPage = null, renderData = {}) => {
  const token = signToken(user._id);
  
  const cookieOptions = {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000), 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict' 
  };

  res.cookie('jwt', token, cookieOptions);
  user.password = undefined;

  if (renderPage) {
    res.render(renderPage, renderData);
  } else {
    res.status(statusCode).json({
      status: 'success',
      token,
      data: {
        user
      }
    });
  }
};


const protect = async (req, res, next) => {
  try {
    
    let token = req.cookies.jwt;

    if (!token) {
      return res.redirect('/login');
    }

    
    const decoded = jwt.verify(token, JWT_SECRET);

    
    const currentUser = await User.findById(decoded.userId);
    if (!currentUser) {
      return res.redirect('/login');
    }

   
    req.user = currentUser;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
   
    res.clearCookie('jwt');
    return res.redirect('/login');
  }
};


const isLoggedIn = async (req, res, next) => {
  try {
    if (req.cookies.jwt) {
      const decoded = jwt.verify(req.cookies.jwt, JWT_SECRET);
      const currentUser = await User.findById(decoded.userId);
      
      if (currentUser) {
        req.user = currentUser;
        res.locals.user = currentUser;
        return next();
      }
    }
  } catch (error) {
    
    res.clearCookie('jwt');
  }
  
  res.locals.user = null;
  next();
};


function validatePassword(password) {
  const minLength = 6;
  const maxLength = 20;
  
  
  if (password.length < minLength || password.length > maxLength) {
    return {
      isValid: false,
      message: `Password must be between ${minLength} and ${maxLength} characters long`
    };
  }
  
  
  if (!/[a-z]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one lowercase letter'
    };
  }
  
 
  if (!/[A-Z]/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one uppercase letter'
    };
  }
  
  
  if (!/\d/.test(password)) {
    return {
      isValid: false,
      message: 'Password must contain at least one number'
    };
  }
  
  return { isValid: true };
}


function validateEmail(email) {
  return validator.isEmail(email);
}


app.use(isLoggedIn);

app.get("/", function(req, res){
  
  if (req.user) {
    return res.redirect('/dashboard');
  }
  res.render("home");
});

app.get("/login", function(req, res){
 
  if (req.user) {
    return res.redirect('/dashboard');
  }
  res.render("login", { error: null });
});

app.get("/register", function(req, res){
  
  if (req.user) {
    return res.redirect('/dashboard');
  }
  res.render("register", { error: null });
});


app.post("/login", async function(req, res) {
  const email = req.body.username;
  const password = req.body.password;

  try {
   
    if (!validateEmail(email)) {
      return res.render("login", { 
        error: "Please enter a valid email address" 
      });
    }

    
    if (!password) {
      return res.render("login", { 
        error: "Password is required" 
      });
    }

    
    const foundUser = await User.findOne({ email: email.toLowerCase() });

    if (!foundUser) {
      return res.render("login", { 
        error: "No account found with this email address" 
      });
    }

    
    const isPasswordValid = await foundUser.comparePassword(password);

    if (isPasswordValid) {
      
      createAndSendToken(foundUser, 200, res, "dashboard", {
        user: {
          name: foundUser.name,
          email: foundUser.email,
          memberSince: foundUser.createdAt.toDateString()
        }
      });
    } else {
      res.render("login", { 
        error: "Incorrect password" 
      });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.render("login", { 
      error: "An error occurred during login. Please try again." 
    });
  }
});


app.post("/register", async function(req, res) {
  const name = req.body.name;
  const email = req.body.username;
  const password = req.body.password;

  try {
    
    if (!name || name.trim().length < 2) {
      return res.render("register", { 
        error: "Name must be at least 2 characters long" 
      });
    }

    
    if (!validateEmail(email)) {
      return res.render("register", { 
        error: "Please enter a valid email address" 
      });
    }

   
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.render("register", { 
        error: passwordValidation.message 
      });
    }

    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.render("register", { 
        error: "An account with this email already exists" 
      });
    }

    
    const newUser = new User({
      name: name.trim(),
      email: email.toLowerCase(),
      password: password 
    });

    await newUser.save();
    console.log("User registered successfully:", email);
    
    
    res.render("login", { 
      success: "Registration successful! Please log in with your credentials.",
      error: null 
    });

  } catch (err) {
    console.log("Registration error:", err);
    
    if (err.code === 11000) {
      
      res.render("register", { 
        error: "An account with this email already exists" 
      });
    } else {
      res.render("register", { 
        error: "Registration failed. Please try again." 
      });
    }
  }
});


app.get("/dashboard", protect, function(req, res){
  res.render("dashboard", { 
    user: {
      name: req.user.name,
      email: req.user.email,
      memberSince: req.user.createdAt.toDateString()
    }
  });
});


app.get("/secrets", protect, async function(req, res){
  try {
   
    const secrets = await Secret.find({})
      .populate('submittedBy', 'email')
      .sort({ submittedAt: -1 })
      .exec();
    
    res.render("secrets", { secrets: secrets });
  } catch (error) {
    console.error("Error fetching secrets:", error);
    res.render("secrets", { secrets: [] });
  }
});


app.get("/submit", protect, function(req, res){
  res.render("submit");
});

app.post("/submit", protect, async function(req, res){
  try {
    const secretContent = req.body.secret;
    
    
    if (!secretContent || secretContent.trim().length === 0) {
      return res.render("submit", { 
        error: "Please enter a secret before submitting." 
      });
    }
    
   
    const newSecret = new Secret({
      content: secretContent.trim(),
      submittedBy: req.user._id,
      isAnonymous: true 
    });
    
    await newSecret.save();
    console.log("Secret submitted by:", req.user.email);
    
    res.redirect("/secrets");
  } catch (error) {
    console.error("Error submitting secret:", error);
    res.render("submit", { 
      error: "Failed to submit secret. Please try again." 
    });
  }
});


app.get("/logout", function(req, res){
  res.clearCookie('jwt', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.redirect("/login");
});

app.listen(5000, function(){
  console.log("Server started on port 5000");
});