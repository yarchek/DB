const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const Sequelize = require('sequelize');
const config = require('./config');

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');

const passport = require('passport');
const passportJWT = require('passport-jwt');

const sequelize = new Sequelize(config.mysqlUrl);

sequelize
    .authenticate()
    .then(() => {
      console.log('Connection has been established successfully.');
    })
    .catch(err => {
      console.error('Unable to connect to the database:', err);
    });


const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = config.secretKey;

const strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next) {
  console.log('payload received', jwt_payload);
  let user = getUser({ id: jwt_payload.id });

  if (user) {
    next(null, user);
  } else {
    next(null, false);
  }
});

passport.use(strategy);

const app = express();

app.use(passport.initialize());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const profileTypes = sequelize.define('profile_type', {
  id_profile_type: {
    type: Sequelize.NUMBER,
    allowNull: true,
    validate: {
      isNumeric: true
    }
  },
  name: {
    type: Sequelize.STRING,
    allowNull: false,
    validate: {
      isAlpha: true
    }
  }
});

const profile = sequelize.define('profile', {
  /*id_profile: {
    type: Sequelize.NUMBER,
    allowNull: true,
    validate: {
      isNumeric: true
    }
  },*/
  id: {
    type: Sequelize.NUMBER,
    allowNull: true,
    primaryKey: true,
    validate: {
      isNumeric: true
    }
  },
  login: {
    type: Sequelize.STRING,
    allowNull: true
  },
  password: {
    type: Sequelize.STRING,
    allowNull: true
  },
  id_profile_type: {
    type: Sequelize.NUMBER,
    allowNull: true,
    defaultValue: 1,
    validate: {
      isNumeric: true
    }
  }
});

const permissions = sequelize.define('permission', {
  id_type: {
    type: Sequelize.NUMBER,
    allowNull: false,
    validate: {
      isNumeric: true
    }
  },
  id_profile_type: {
    type: Sequelize.NUMBER,
    allowNull: false,
    validate: {
      isNumeric: true
    }
  },
  permission: {
    type: Sequelize.BOOLEAN,
    allowNull: false
  }
});

const types = sequelize.define('type', {
  id_type: {
    type: Sequelize.NUMBER,
    allowNull: true,
    validate: {
      isNumeric: true
    }
  },
  type: {
    type: Sequelize.STRING,
    allowNull: false,
  },
  data_type: {
    type: Sequelize.STRING,
    allowNull: false
  }
});

const elemData = sequelize.define('data_elem', {
  id_elem: {
    type: Sequelize.NUMBER,
    allowNull: true,
    validate: {
      isNumeric: true
    }
  },
  elem: {
    type: Sequelize.STRING,
    allowNull: false
  },
  id_profile: {
    type: Sequelize.NUMBER,
    allowNull: false,
    validate: {
      isNumeric: true
    }
  },
  id_type: {
    type: Sequelize.NUMBER,
    allowNull: false
  }
});
/*
const create = async ( model, {obj} ) => {
  return await model.create({obj});
};

const getAll = async (model) => {
  return await model.findAll();
};

const getSmth = async (model, obj) => {
  return await model.findOne({
    where: obj
  });
};
*/
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', function(req, res) {
  res.json({ message: 'Express is up!' });
});

// get all users
app.get('/profile', function(req, res) {
  getAll(profile).then(user => res.json(user));
});

app.post('/register', (req, res, next) => {
  profile.create({
    login: req.body.login,
    password: req.body.password,
    id_profile_type: req.body.id_profile_type
  })
      .then(user =>
      res.json({ user, msg: 'Account created successfully', success: true})
  )
      .catch((err) => {
        res.json({err: err});
      });
});

app.post('/login', async function(req, res, next) {
  if (req.body.login && req.body.password) {
    let user = await getSmth(profile, { name: name });
    if (!user) {
      res.status(401).json({ message: 'No such user found' });
    }
    if (user.password === req.body.password) {
      // from now on we'll identify the user by the id and the id is the
      // only personalized value that goes into our token
      const payload = { id: user.id };
      const token = jwt.sign(payload, jwtOptions.secretOrKey);
      res.json({ msg: 'ok', token: token });
    } else {
      res.status(401).json({ msg: 'Password is incorrect' });
    }
  }
});

const validAuth = passport.authenticate('jwt', { session: false });

const userIsBuhgalter = (req, res, next) => {
  if (req.user.id_profile_type === 2) {
    return next();
  } else {
    const err = new Error('You are not authorized to perform this operation!');
    err.status = 403;
    return next(err);
  }
};

const userIsAdmin = (req, res, next) => {
  if (req.user.id_profile_type === 3) {
    return next();
  } else {
    const err = new Error('You are not authorized to perform this operation!');
    err.status = 403;
    return next(err);
  }
};

app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.json('Success! You can now see this without a token.');
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
