const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult, param, query } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'QA_JSONWEBTOKEN';

// ===== CONSTANTS =====
const ROLES = ['admin', 'user', 'manager', 'supervisor', 'employee'];
const POSITIONS = [
  'Frontend Developer', 'Backend Developer', 'Full Stack Developer',
  'DevOps Engineer', 'Product Manager', 'UI/UX Designer',
  'Data Analyst', 'QA Engineer', 'System Administrator',
  'Marketing Specialist', 'Sales Representative', 'HR Manager',
  'Financial Analyst', 'Business Analyst', 'Project Manager'
];

// ===== MIDDLEWARE SETUP =====
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors());

// Enhanced rate limiting
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: {
    success: false,
    error: message,
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = createRateLimit(15 * 60 * 1000, 100, 'Too many requests from this IP, please try again later.');
const loginLimiter = createRateLimit(15 * 60 * 1000, 5, 'Too many login attempts, please try again later.');

app.use(generalLimiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.path} - IP: ${req.ip} - User-Agent: ${req.get('User-Agent')}`);
  next();
});

// ===== DATA STORE =====
let users = [
  {
    id: 1,
    name: "Ali Ahmed",
    email: "ali@example.com",
    password: bcrypt.hashSync("password", 12),
    role: "admin",
    age: 28,
    workplace: "Tech Solutions Inc.",
    position: "Full Stack Developer",
    salary: 75000,
    department: "Engineering",
    phoneNumber: "+964-770-123-4567",
    address: "Baghdad, Iraq",
    hireDate: "2022-01-15",
    emergencyContact: {
      name: "Sara Ahmed",
      phone: "+964-770-987-6543",
      relationship: "Sister"
    },
    skills: ["JavaScript", "Node.js", "React", "MongoDB"],
    createdAt: new Date().toISOString(),
    isActive: true
  },
  {
    id: 2,
    name: "Sara Mohammed",
    email: "sara@example.com",
    password: bcrypt.hashSync("password123", 12),
    role: "user",
    age: 25,
    workplace: "Digital Marketing Agency",
    position: "Marketing Specialist",
    salary: 45000,
    department: "Marketing",
    phoneNumber: "+964-771-234-5678",
    address: "Basra, Iraq",
    hireDate: "2023-03-10",
    emergencyContact: {
      name: "Ahmed Mohammed",
      phone: "+964-771-876-5432",
      relationship: "Father"
    },
    skills: ["Digital Marketing", "SEO", "Content Writing", "Analytics"],
    createdAt: new Date().toISOString(),
    isActive: true
  }
];

// ===== UTILITY FUNCTIONS =====
const createResponse = (success, message, data = null, error = null, code = null) => {
  const response = { success, message };
  if (data) response.data = data;
  if (error) response.error = error;
  if (code) response.code = code;
  return response;
};

const removePassword = (user) => {
  const { password, ...userWithoutPassword } = user;
  return userWithoutPassword;
};

const generateUserId = () => Date.now();

// ===== MIDDLEWARE =====
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json(createResponse(
      false,
      'Access token required',
      null,
      'Access token required',
      'TOKEN_MISSING'
    ));
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json(createResponse(
        false,
        'Invalid or expired token',
        null,
        'Invalid or expired token',
        'TOKEN_INVALID'
      ));
    }
    req.user = user;
    next();
  });
};

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json(createResponse(
      false,
      'Validation failed',
      { details: errors.array() },
      'Validation failed',
      'VALIDATION_ERROR'
    ));
  }
  next();
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json(createResponse(
      false,
      'Admin access required',
      null,
      'Admin access required',
      'INSUFFICIENT_PERMISSIONS'
    ));
  }
  next();
};

const loginValidationRules = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password is required')
];

const userValidationRules = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be 2-100 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 6, max: 100 })
    .withMessage('Password must be 6-100 characters'),
  body('role')
    .optional()
    .isIn(ROLES)
    .withMessage(`Role must be one of: ${ROLES.join(', ')}`),
  body('age')
    .optional()
    .isInt({ min: 18, max: 100 })
    .withMessage('Age must be between 18 and 100'),
  body('workplace')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Workplace must be 2-100 characters'),
  body('position')
    .optional()
    .isIn(POSITIONS)
    .withMessage('Position must be one of the predefined positions'),
  body('salary')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Salary must be a positive number'),
  body('department')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Department must be 2-50 characters'),
  body('phoneNumber')
    .optional()
    .matches(/^[\d\s\-\(\)\+]+$/)
    .withMessage('Invalid phone number format'),
  body('address')
    .optional()
    .trim()
    .isLength({ min: 5, max: 200 })
    .withMessage('Address must be 5-200 characters'),
  body('hireDate')
    .optional()
    .isISO8601()
    .withMessage('Hire date must be a valid date'),
  body('emergencyContact.name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Emergency contact name must be 2-100 characters'),
  body('emergencyContact.phone')
    .optional()
    .matches(/^[\d\s\-\(\)\+]+$/)
    .withMessage('Invalid emergency contact phone format'),
  body('emergencyContact.relationship')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Relationship must be 2-50 characters'),
  body('skills')
    .optional()
    .isArray()
    .withMessage('Skills must be an array'),
  body('skills.*')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Each skill must be 1-50 characters')
];

const updateUserValidationRules = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('Valid user ID is required'),
  ...userValidationRules.map(rule => {

    if (rule.builder.fields[0] !== 'id') {
      return rule.optional();
    }
    return rule;
  }).filter(rule => rule.builder.fields[0] !== 'password')
];

const getUserValidationRules = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('Valid user ID is required')
];

const getUsersValidationRules = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('role')
    .optional()
    .custom((value) => {
      if (value && !ROLES.includes(value)) {
        throw new Error(`Role must be one of: ${ROLES.join(', ')}`);
      }
      return true;
    }),
  query('department')
    .optional()
    .custom((value) => {
      if (value && (value.length < 1 || value.length > 50)) {
        throw new Error('Department must be 1-50 characters');
      }
      return true;
    }),
  query('search')
    .optional()
    .custom((value) => {
      if (value && (value.length < 1 || value.length > 100)) {
        throw new Error('Search term must be 1-100 characters');
      }
      return true;
    })
];

app.get('/metadata', (req, res) => {
  try {
    const metadata = {
      roles: ROLES,
      positions: POSITIONS,
      apiVersion: '1.0.0',
      endpoints: {
        auth: ['/login'],
        users: ['/users', '/users/:id'],
        stats: ['/users/stats/overview']
      }
    };

    res.json(createResponse(true, 'Metadata retrieved successfully', metadata));
  } catch (error) {
    console.error('Metadata error:', error);
    res.status(500).json(createResponse(
      false,
      'Failed to retrieve metadata',
      null,
      'Internal server error',
      'METADATA_ERROR'
    ));
  }
});

app.post('/login',
  loginLimiter,
  loginValidationRules,
  handleValidationErrors,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = users.find(u => u.email === email && u.isActive);
      if (!user) {
        return res.status(401).json(createResponse(
          false,
          'Invalid credentials',
          null,
          'Invalid credentials',
          'INVALID_CREDENTIALS'
        ));
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json(createResponse(
          false,
          'Invalid credentials',
          null,
          'Invalid credentials',
          'INVALID_CREDENTIALS'
        ));
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      user.lastLogin = new Date().toISOString();

      const loginData = {
        user: removePassword(user),
        token,
        expiresIn: '24h'
      };

      res.json(createResponse(true, 'Login successful', loginData));

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json(createResponse(
        false,
        'Login failed',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.get('/users',
  authenticateToken,
  getUsersValidationRules,
  handleValidationErrors,
  (req, res) => {
    try {
      const { page = 1, limit = 10, role, department, search } = req.query;
      const offset = (page - 1) * limit;

      let filteredUsers = users.filter(user => user.isActive);

      // Apply filters
      if (role) {
        filteredUsers = filteredUsers.filter(user => user.role === role);
      }
      if (department) {
        filteredUsers = filteredUsers.filter(user =>
          user.department && user.department.toLowerCase().includes(department.toLowerCase())
        );
      }
      if (search) {
        const searchLower = search.toLowerCase();
        filteredUsers = filteredUsers.filter(user =>
          user.name.toLowerCase().includes(searchLower) ||
          user.email.toLowerCase().includes(searchLower) ||
          (user.position && user.position.toLowerCase().includes(searchLower))
        );
      }

      const paginatedUsers = filteredUsers
        .slice(offset, offset + parseInt(limit))
        .map(removePassword);

      const responseData = {
        users: paginatedUsers,
        pagination: {
          total: filteredUsers.length,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(filteredUsers.length / limit),
          hasNext: offset + parseInt(limit) < filteredUsers.length,
          hasPrev: page > 1
        },
        filters: { role, department, search }
      };

      res.json(createResponse(true, 'Users retrieved successfully', responseData));

    } catch (error) {
      console.error('Get users error:', error);
      res.status(500).json(createResponse(
        false,
        'Failed to retrieve users',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.get('/users/:id',
  authenticateToken,
  getUserValidationRules,
  handleValidationErrors,
  (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const user = users.find(u => u.id === id && u.isActive);

      if (!user) {
        return res.status(404).json(createResponse(
          false,
          'User not found',
          null,
          'User not found',
          'USER_NOT_FOUND'
        ));
      }

      res.json(createResponse(true, 'User retrieved successfully', removePassword(user)));

    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json(createResponse(
        false,
        'Failed to retrieve user',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.post('/users',
  authenticateToken,
  adminOnly,
  userValidationRules,
  handleValidationErrors,
  async (req, res) => {
    try {
      const {
        name, email, password, role = 'user', age, workplace, position,
        salary, department, phoneNumber, address, hireDate, emergencyContact, skills
      } = req.body;


      // Check if user already exists
      if (users.find(u => u.email === email)) {
        return res.status(409).json(createResponse(
          false,
          'User with this email already exists',
          null,
          'User with this email already exists',
          'EMAIL_EXISTS'
        ));
      }

      const hashedPassword = await bcrypt.hash(password, 12);

      const newUser = {
        id: generateUserId(),
        name: name.trim(),
        email,
        password: hashedPassword,
        role,
        age,
        workplace: workplace?.trim(),
        position,
        salary,
        department: department?.trim(),
        phoneNumber,
        address: address?.trim(),
        hireDate,
        emergencyContact,
        skills: skills || [],
        createdAt: new Date().toISOString(),
        isActive: true
      };

      users.push(newUser);

      res.status(201).json(createResponse(
        true,
        'User created successfully',
        removePassword(newUser)
      ));

    } catch (error) {
      console.error('Create user error:', error);
      res.status(500).json(createResponse(
        false,
        'Failed to create user',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.put('/users/:id',
  authenticateToken,
  updateUserValidationRules,
  handleValidationErrors,
  async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const updateData = req.body;

      const userIndex = users.findIndex(u => u.id === id && u.isActive);
      if (userIndex === -1) {
        return res.status(404).json(createResponse(
          false,
          'User not found',
          null,
          'User not found',
          'USER_NOT_FOUND'
        ));
      }

      // Check if email is already taken by another user
      if (updateData.email && users.some(u => u.email === updateData.email && u.id !== id)) {
        return res.status(409).json(createResponse(
          false,
          'Email already taken by another user',
          null,
          'Email already taken by another user',
          'EMAIL_EXISTS'
        ));
      }

      const user = users[userIndex];

      // Check permissions: users can only update themselves, admins can update anyone
      if (req.user.role !== 'admin' && req.user.id !== id) {
        return res.status(403).json(createResponse(
          false,
          'You can only update your own profile',
          null,
          'You can only update your own profile',
          'INSUFFICIENT_PERMISSIONS'
        ));
      }

      // Update fields
      Object.keys(updateData).forEach(key => {
        if (key === 'password') {
          user[key] = bcrypt.hashSync(updateData[key], 12);
        } else if (key === 'name' || key === 'workplace' || key === 'department' || key === 'address') {
          user[key] = updateData[key]?.trim();
        } else {
          user[key] = updateData[key];
        }
      });

      user.updatedAt = new Date().toISOString();

      res.json(createResponse(
        true,
        'User updated successfully',
        removePassword(user)
      ));

    } catch (error) {
      console.error('Update user error:', error);
      res.status(500).json(createResponse(
        false,
        'Failed to update user',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.delete('/users/:id',
  authenticateToken,
  adminOnly,
  getUserValidationRules,
  handleValidationErrors,
  (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const user = users.find(u => u.id === id && u.isActive);

      if (!user) {
        return res.status(404).json(createResponse(
          false,
          'User not found',
          null,
          'User not found',
          'USER_NOT_FOUND'
        ));
      }

      // Prevent admin from deleting themselves
      if (user.id === req.user.id) {
        return res.status(400).json(createResponse(
          false,
          'Cannot delete your own account',
          null,
          'Cannot delete your own account',
          'SELF_DELETE_ERROR'
        ));
      }

      user.isActive = false;
      user.deletedAt = new Date().toISOString();
      user.deletedBy = req.user.id;

      res.json(createResponse(true, 'User deleted successfully', { id: user.id }));

    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json(createResponse(
        false,
        'Failed to delete user',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.get('/users/stats/overview',
  authenticateToken,
  adminOnly,
  (req, res) => {
    try {
      const activeUsers = users.filter(u => u.isActive);

      const stats = {
        totalUsers: activeUsers.length,
        totalDeletedUsers: users.filter(u => !u.isActive).length,
        roleDistribution: ROLES.reduce((acc, role) => {
          acc[role] = activeUsers.filter(u => u.role === role).length;
          return acc;
        }, {}),
        departmentDistribution: {},
        averageAge: 0,
        averageSalary: 0,
        recentUsers: activeUsers
          .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
          .slice(0, 5)
          .map(removePassword)
      };

      // Department distribution
      activeUsers.forEach(user => {
        if (user.department) {
          stats.departmentDistribution[user.department] =
            (stats.departmentDistribution[user.department] || 0) + 1;
        }
      });

      // Calculate averages
      const usersWithAge = activeUsers.filter(u => u.age);
      const usersWithSalary = activeUsers.filter(u => u.salary);

      if (usersWithAge.length > 0) {
        stats.averageAge = Math.round(
          usersWithAge.reduce((sum, u) => sum + u.age, 0) / usersWithAge.length
        );
      }

      if (usersWithSalary.length > 0) {
        stats.averageSalary = Math.round(
          usersWithSalary.reduce((sum, u) => sum + u.salary, 0) / usersWithSalary.length
        );
      }

      res.json(createResponse(true, 'Statistics retrieved successfully', stats));

    } catch (error) {
      console.error('Get stats error:', error);
      res.status(500).json(createResponse(
        false,
        'Failed to retrieve statistics',
        null,
        'Internal server error',
        'SERVER_ERROR'
      ));
    }
  }
);

app.use((error, req, res, next) => {
  console.error('Global error handler:', error);

  if (error.message === 'Not allowed by CORS') {
    return res.status(403).json(createResponse(
      false,
      'CORS policy violation',
      null,
      'CORS policy violation',
      'CORS_ERROR'
    ));
  }

  if (error.type === 'entity.parse.failed') {
    return res.status(400).json(createResponse(
      false,
      'Invalid JSON format',
      null,
      'Invalid JSON format',
      'INVALID_JSON'
    ));
  }

  res.status(500).json(createResponse(
    false,
    'Internal server error',
    null,
    'Internal server error',
    'SERVER_ERROR'
  ));
});

app.use('*', (req, res) => {
  res.status(404).json(createResponse(
    false,
    'Route not found',
    null,
    `Route ${req.originalUrl} not found`,
    'ROUTE_NOT_FOUND'
  ));
});

process.on('SIGINT', () => {
  console.log('\n🛑 Gracefully shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Gracefully shutting down...');
  process.exit(0);
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`👥 Total active users: ${users.filter(u => u.isActive).length}`);
    console.log(`🔐 Available test users:`);
    users.forEach(user => {
      console.log(`   📧 ${user.email} (${user.role}) - ${user.position || 'N/A'}`);
    });
    console.log(`🔑 Test passwords: "password" and "password123"`);
    console.log(`📋 Available roles: ${ROLES.join(', ')}`);
    console.log(`💼 Available positions: ${POSITIONS.length} positions available`);
    console.log(`🛡️  JWT Secret: ${JWT_SECRET === 'QA_JsonWebToken' ? '⚠️  Using default (change in production!)' : '✅ Custom secret configured'}`);
  });
}

module.exports = app;