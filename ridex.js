const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId} = require('mongodb');
const path = require('path');
const port = 3000;
const bcrypt = require ('bcryptjs');
const saltRounds = 10;
const jwt = require ('jsonwebtoken');
const { pipeline } = require('stream');
require('dotenv').config();


const app = express();
app.use(cors()); 
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;

async function connectToMongoDB() {
    const uri = "mongodb://localhost:27017";
    const client = new MongoClient(uri);

    try {
        await client.connect();
        console.log("✅ Connected to MongoDB!");
        db = client.db("RideX");
        app.locals.db = db;
    } catch (err) {
        console.error("❌ MongoDB connection error:", err);
    }
}
connectToMongoDB();

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public'));
});

// --- API ROUTES ---

///RBAC middleware
const authenticate = (req, res, next) =>{
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) return res.status(401).json({error: "Unauthorized"});

    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch(err){
        res.status(401).json({ error: "Invalid token"});
    }
};

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role))
        return res.status(403).json({error: "Forbidden"});
    next();
};

//---------------------------users---------------------------------//

app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  if (!username || !email || !password || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (!['user', 'admin', 'driver'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified' });
  }

  try {
    const existing = await db.collection('users').findOne({ email });
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.collection('users').insertOne({
      username,
      email,
      password: hashedPassword,
      role,
      createdAt: new Date()
    });

    // Insert into drivers collection
    if (role === 'driver') {
      try {
        await db.collection('drivers').insertOne({
          driverId: result.insertedId,   // ✅ match your DB structure
          name: username,
          email,
          phone: "",                     // can be updated later
          password: hashedPassword,
          status: 'pending',
          vehicle: {
            plateNumber: "",
            model: "",
            color: ""
          },
          createdAt: new Date()
        });
        console.log("✅ Driver inserted into drivers collection");
      } catch (driverErr) {
        console.error("❌ Failed to insert into drivers:", driverErr);
      }
    }


    res.status(201).json({ message: 'Account registered successfully', userId: result.insertedId });
  } catch (err) {
    console.error('❌ Registration error:', err);
    res.status(500).json({ error: 'Failed to register account' });
  }
});

app.post('/auth/login', async (req, res) => {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = await db.collection('users').findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign(
            {userId: user._id, role: user.role},
            process.env.JWT_SECRET,
            {expiresIn: '1h'}
        );

        res.status(200).json({
            token,
            message: 'Login successful',
            userId: user._id,
            username: user.username,
            role: user.role
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/rides', async (req, res) => {
  const {
    customerId,
    pickupLocation,
    destination,
    distance,
    fare,
    scheduledTime
    // intentionally ignoring driverId during ride creation
  } = req.body;

  if (!customerId || !pickupLocation || !destination || distance == null || fare == null) {
    return res.status(400).json({ error: 'Missing required fields: customerId, pickupLocation, destination, distance, or fare' });
  }

  if (typeof distance !== 'number' || distance <= 0) {
    return res.status(400).json({ error: 'Distance must be a positive number' });
  }

  if (typeof fare !== 'number' || fare <= 0) {
    return res.status(400).json({ error: 'Fare must be a positive number' });
  }

  const ride = {
    customerId,
    pickupLocation,
    destination,
    scheduledTime: scheduledTime ? new Date(scheduledTime) : new Date(),
    distance,
    fare,
    status: 'pending',
    createdAt: new Date()
    // 🔥 No driverId included here to keep it unassigned
  };

  try {
    const result = await db.collection('rides').insertOne(ride);
    res.status(201).json({
      message: 'Ride booked successfully',
      rideId: result.insertedId
    });
  } catch (err) {
    console.error('❌ Ride booking error:', err);
    res.status(500).json({ error: 'Failed to book ride' });
  }
});

app.get('/users/:id/rides', authenticate, async (req, res) => {
  const userId = req.params.id;
  try {
    const rides = await db.collection('rides')
      .find({ customerId: userId })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(rides);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch rides' });
  }
});


//----------------------End User------------------------//

//______________________Driver_________________________//

app.put('/drivers/:id/profile', authenticate, authorize(['driver']), async (req, res) => {
  const { name, email, phone, password, vehicle } = req.body;

  if (!name || !email || !phone || !password || !vehicle) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const result = await db.collection('drivers').updateOne(
      { driverId: req.params.id },
      { $set: { name, email, phone, password, vehicle } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "Driver not found or no changes made" });
    }

    res.status(200).json({ message: "Driver profile updated successfully" });
  } catch (err) {
    console.error("Update driver profile error:", err);
    res.status(500).json({ error: "Failed to update driver profile" });
  }
});

app.get('/rides/unassigned', authenticate, authorize(['driver']), async (req, res) => {
  try {
    const rides = await db.collection('rides').find({ driverId: { $exists: false }, status: 'pending' }).toArray();
    res.status(200).json(rides);
  } catch (err) {
    console.error('Error fetching unassigned rides:', err);
    res.status(500).json({ error: 'Failed to load rides' });
  }
});

app.put('/rides/:id/accept', authenticate, authorize(['driver']), async (req, res) => {
  const rideId = req.params.id;
  const driverId = req.user.userId;

  try {
    const result = await db.collection('rides').updateOne(
      { _id: new ObjectId(rideId), driverId: { $exists: false } },
      {
        $set: {
          driverId: driverId,
          status: 'accepted'
        }
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: 'Ride already assigned or not found' });
    }

    res.status(200).json({ message: 'Ride accepted' });
  } catch (err) {
    console.error('Accept ride error:', err);
    res.status(500).json({ error: 'Failed to accept ride' });
  }
});

app.put('/drivers/:id/vehicle', authenticate, authorize(['driver']), async (req, res) => {
  const driverId = req.params.id;  // This is the userId from localStorage
  const vehicle = req.body.vehicle;

  try {
    const result = await db.collection('drivers').updateOne(
      { driverId: driverId }, // ✅ Match by driverId field (not _id)
      { $set: { vehicle: vehicle } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "Driver not found or no changes made" });
    }

    res.status(200).json({ message: "Vehicle updated successfully" });
  } catch (err) {
    console.error("Vehicle update error:", err);
    res.status(500).json({ error: "Failed to update vehicle details" });
  }
});

app.put('/rides/:id/ridestatus', async (req, res) => {
    try {
        const result = await db.collection('rides').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status: 'completed' } }
        );

        res.status(200).json({ updated: result.modifiedCount });
    } catch (err) {
        res.status(400).json({ error: "Failed to mark ride as completed" });
    }
});

//------------------------------End Drivers----------------------------//

//===============================ADMIN===============================//

app.put('/drivers/:id/status', async (req, res) => {
    const { status } = req.body;
    
    if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status value. Must be "approved" or "rejected".' });
    }

    try {
        const result = await db.collection('drivers').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status: status } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: "Driver not found or already updated" });
        }

        res.status(200).json({ message: `Driver status updated to ${status}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update driver status" });
    }
});

app.get('/admin/users', authenticate, authorize(['admin']), async (req, res) => {
    try {
      const users = await db.collection('users').find().toArray();
      res.status(200).json(users);
    } catch (err) {
      console.error('Fetch users error:', err);
      res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/admin/drivers', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const drivers = await db.collection('drivers').find().toArray();
    res.status(200).json(drivers);
  } catch (err) {
    console.error('Fetch drivers error:', err);
    res.status(500).json({ error: 'Failed to fetch drivers' });
  }
});


app.put('/users/:id', async (req, res) => {
    try {
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: req.body }
        );
        res.status(200).json({ updated: result.modifiedCount });
    } catch (err) {
        res.status(400).json({ error: 'Failed to update user' });
    }
});

app.delete('/admin/users/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const result = await db.collection('users').deleteOne({
            _id: new ObjectId(req.params.id)
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error('❌ Delete user error:', err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/analytics/passengers', async (req, res, next) => {
  try {
    const db = req.app.locals.db;

    const pipeline = [
      {
        $group: {
          _id: '$customerId',
          totalRides: { $sum: 1 },
          totalFare: { $sum: '$fare' },
          avgDistance: { $avg: '$distance' },
        },
      },

      {
        $project: {
          _id: 0,
          name: '$_id',
          totalRides: 1,
          totalFare: 1,
          avgDistance: { $round: ['$avgDistance', 2] },
        },
      },
    ];

    const result = await db.collection('rides').aggregate(pipeline).toArray();
    res.json(result);
  } catch (err) {
    next(err);
  }
});


//_______________________________ADMIN_________________________________//

app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});